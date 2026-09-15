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
	"mcpx/internal/remotesession"
	"mcpx/internal/security"
)

type approvedCommandExecutor func(context.Context, time.Duration) (*mcp.CallToolResult, error)

func (r *Runtime) executeWithCommandConfirmation(
	ctx context.Context,
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
			ctx, envReq, principal, remote, command, purpose, scope, commandDigest,
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
		retryArguments := map[string]any{
			"remote_session_id": remote.ID, "action": "run", "command": command,
			"purpose": purpose, "scope": scope, "user_confirmed": true,
		}
		if runtimeSpec != nil {
			retryArguments = runtimeConfirmationRetryArguments(remote.ID, purpose, scope, runtimeSpec)
		}
		addCommandAuthorizationRetryArguments(retryArguments, authorizationState)
		addRecoveryAction(
			&response,
			"execute",
			"用户确认后使用相同 command/task 或 runtime+script、purpose、authorization 边界和 remote_session_id 重试，并设置 user_confirmed=true",
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
