package server

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/approval"
	"mcpx/internal/audit"
	"mcpx/internal/auth"
	"mcpx/internal/envelope"
	"mcpx/internal/mcpresult"
	"mcpx/internal/remotesession"
	"mcpx/internal/security"
)

type approvedCommandExecutor func(context.Context, time.Duration) (*mcp.CallToolResult, error)

func (r *Runtime) executeWithCommandConfirmation(
	ctx context.Context,
	req *mcp.CallToolRequest,
	envReq envelope.Request,
	principal auth.Principal,
	remote remotesession.Session,
	command, purpose, scope, commandDigest string,
	analysis security.CommandAnalysis,
	runtimeSpec *ephemeralRuntimeSpec,
	yield time.Duration,
	authorizationState commandAuthorizationState,
	executeApproved approvedCommandExecutor,
) (*mcp.CallToolResult, error) {
	needsConfirmation := analysis.Decision == security.Confirm || authorizationState.Request != nil
	if authorizationState.matchedGrant() && analysis.Decision == security.Confirm {
		needsConfirmation = false
	}
	if !needsConfirmation {
		return executeApproved(ctx, yield)
	}
	if isCleanCoreRequest(ctx) {
		return r.executeCleanCommandConfirmation(
			ctx, req, envReq, principal, remote, command, purpose, scope, commandDigest,
			analysis, runtimeSpec, yield, authorizationState, executeApproved,
		)
	}
	return r.executeLegacyCommandConfirmation(
		ctx, envReq, principal, remote, command, purpose, scope, commandDigest,
		analysis, yield, executeApproved,
	)
}

func (r *Runtime) executeCleanCommandConfirmation(
	ctx context.Context,
	req *mcp.CallToolRequest,
	envReq envelope.Request,
	principal auth.Principal,
	remote remotesession.Session,
	command, purpose, scope, commandDigest string,
	analysis security.CommandAnalysis,
	runtimeSpec *ephemeralRuntimeSpec,
	yield time.Duration,
	authorizationState commandAuthorizationState,
	executeApproved approvedCommandExecutor,
) (*mcp.CallToolResult, error) {
	userConfirmed := boolPayload(envReq.Payload, "user_confirmed")
	pending, pendingOK := r.pendingCommandConfirmation(remote.ID, principal.ID, command, scope, commandDigest)
	if !userConfirmed || !pendingOK {
		if !pendingOK {
			var confirmationErr error
			pending, confirmationErr = r.approvals.PutPending(approval.Pending{
				Tool: "command_execute", Summary: command, Command: command,
				CommandYieldMs: int(yield / time.Millisecond), Purpose: purpose, Scope: scope,
				CommandDigest: commandDigest, WorkDir: remote.WorkspacePath,
				RequestID: envReq.RequestID, Workspace: remote.WorkspaceName,
				RemoteSessionID: remote.ID, PrincipalID: principal.ID,
				ContentKey: cleanCommandConfirmationContentKey(principal.ID, commandDigest),
			})
			if confirmationErr != nil {
				return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "confirmation_store_error", confirmationErr.Error())
			}
		}
		confirmationData := map[string]any{
			"command": command, "purpose": purpose, "scope": scope,
			"command_digest": commandDigest, "pending_digest": commandDigest,
			"command_policy":        commandPolicyData(analysis),
			"confirmation_required": true, "user_confirmed_required": true,
			"summary": "执行已完成策略预检；请向用户展示命令或临时脚本摘要及用途，确认后将 user_confirmed=true 原样重试。",
		}
		if authorizationState.Presented {
			confirmationData["authorization"] = authorizationState.data()
		}
		addRuntimeConfirmationData(confirmationData, runtimeSpec)
		if authorizationState.Presented {
			if err := r.writeAudit(audit.Event{
				RequestID: envReq.RequestID, RemoteSessionID: remote.ID, Workspace: remote.WorkspaceName,
				Tool: "execute", Command: command, Status: "authorization_confirmation_required",
				Detail: map[string]any{
					"command_digest": commandDigest,
					"purpose":        purpose,
					"scope":          scope,
					"authorization":  authorizationState.data(),
				},
			}); err != nil {
				return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "audit_write_failed", "authorization confirmation audit could not be persisted")
			}
		}
		response := envelope.Fail(
			envelope.StatusNeedConfirmation,
			envReq.RequestID,
			remote.WorkspaceName,
			confirmationData,
			"USER_CONFIRMATION_REQUIRED",
			"命令执行等待用户语义确认",
		)
		response.RemoteSessionID = remote.ID
		if runtimeSpec != nil {
			confirmationData["summary"] = "临时脚本等待用户确认；服务端不保存脚本正文，也不提供可直接执行的重试模板。调用方须回读已保存的完整原始请求与脚本，核对 script_sha256、script_bytes、Workspace 身份并保留全部业务参数、remote_session_id 和 idempotency_key；获准后仅将 user_confirmed 改为 true。原始请求缺失或校验失败时停止，不得重建等价脚本或换 key 重跑。"
			return r.resultJSON(response)
		}
		// 原样保留调用参数、授权边界、Activity 与幂等身份，避免恢复模板改变请求指纹。
		retryArguments := mcpresult.Arguments(req)
		retryArguments["user_confirmed"] = true
		addRecoveryAction(
			&response,
			"execute",
			"用户确认后保留完整原始请求及 idempotency_key，仅设置 user_confirmed=true；重试不得换 key 或改写参数",
			retryArguments,
		)
		return r.resultJSON(response)
	}

	if authorizationState.Request != nil {
		activated, activationErr := r.activateCommandAuthorization(
			ctx, envReq, principal, remote, command, commandDigest, authorizationState,
		)
		if activationErr != nil {
			return r.terminalErrorForContext(
				ctx, envReq, remote.ID, remote.WorkspaceName,
				"authorization_store_error",
				fmt.Sprintf("confirmed authorization grant could not be activated: %v", activationErr),
			)
		}
		authorizationState = activated
		ctx = withCommandAuthorization(ctx, authorizationState)
	}
	result, executeErr := executeApproved(ctx, yield)
	if executeErr == nil {
		if _, consumed := r.approvals.Consume(pending.ID); !consumed {
			return r.terminalError(
				envReq, remote.ID, remote.WorkspaceName,
				"confirmation_state_error",
				"confirmed command approval could not be consumed",
			)
		}
	}
	return result, executeErr
}

func (r *Runtime) executeLegacyCommandConfirmation(
	ctx context.Context,
	envReq envelope.Request,
	principal auth.Principal,
	remote remotesession.Session,
	command, purpose, scope, commandDigest string,
	analysis security.CommandAnalysis,
	yield time.Duration,
	executeApproved approvedCommandExecutor,
) (*mcp.CallToolResult, error) {
	confirmationToken := stringPayload(envReq.Payload, "confirmation_token")
	if !r.hasPendingCommandConfirmation(remote.ID, principal.ID, command, purpose, scope, confirmationToken) {
		pending, confirmationErr := r.approvals.PutPending(approval.Pending{
			Tool: "command_execute", Summary: command, Command: command,
			CommandYieldMs: int(yield / time.Millisecond), Purpose: purpose, Scope: scope,
			CommandDigest: commandDigest, WorkDir: remote.WorkspacePath,
			RequestID: envReq.RequestID, Workspace: remote.WorkspaceName,
			RemoteSessionID: remote.ID, PrincipalID: principal.ID,
		})
		if confirmationErr != nil {
			return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "confirmation_store_error", confirmationErr.Error())
		}
		message := "confirmation_token: " + pending.ConfirmationToken + "；请向用户展示命令及用途，获得明确语义确认后，使用相同 command 和该 confirmation_token 重试。该 token 仅绑定本次操作，不承担认证职责。"
		if confirmationToken != "" {
			message = "你提供的 confirmation_token 未匹配当前待确认项；请使用本响应 data.confirmation_token 中的完整 token 原样重试：" + pending.ConfirmationToken + "（相同 command、remote_session_id 和 scope）。"
		}
		data := commandConfirmationData{
			ConfirmationToken:    pending.ConfirmationToken,
			Command:              command,
			Purpose:              purpose,
			Scope:                scope,
			CommandDigest:        commandDigest,
			CommandPolicy:        commandPolicyData(analysis),
			ConfirmationRequired: true,
			ConfirmationMessage:  message,
		}
		response := envelope.Fail(
			envelope.StatusNeedConfirmation,
			envReq.RequestID,
			remote.WorkspaceName,
			data,
			"USER_CONFIRMATION_REQUIRED",
			"命令执行等待用户语义确认",
		)
		response.RemoteSessionID = remote.ID
		return r.resultJSON(response)
	}
	result, executeErr := executeApproved(ctx, yield)
	if executeErr == nil {
		r.consumePendingCommandConfirmation(remote.ID, principal.ID, command, purpose, scope, confirmationToken)
	}
	return result, executeErr
}
