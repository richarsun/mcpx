package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"mcpx/internal/authorization"
	"mcpx/internal/security"
)

func (state commandAuthorizationState) data() map[string]any {
	data := map[string]any{"decision": state.Decision}
	if state.ContextID != "" {
		data["authorization_context_id"] = state.ContextID
	}
	if state.GrantID != "" {
		data["grant_id"] = state.GrantID
	}
	if state.RequestDigest != "" {
		data["authorization_request_digest"] = state.RequestDigest
	}
	if state.Request != nil {
		data["authorization_request"] = authorizationRequestData(*state.Request)
	}
	if state.Grant != nil {
		data["grant"] = authorization.PublicView(*state.Grant)
		data["grant_source"] = map[string]any{
			"grant_id":              state.Grant.ID,
			"grant_digest":          state.Grant.GrantDigest,
			"source_request_id":     state.Grant.SourceRequestID,
			"source_command_digest": state.Grant.SourceCommandDigest,
		}
		grantReused := state.Decision == "grant_reused" || state.Decision == "grant_reused_after_confirmation"
		data["grant_reused"] = grantReused
		data["grant_used_for_confirmation_bypass"] = state.Decision == "grant_reused"
	}
	if len(state.Action.Classes) > 0 || len(state.Action.Repositories) > 0 ||
		len(state.Action.Reasons) > 0 || state.Action.Summary != "" {
		data["action"] = state.Action
	}
	if len(state.Match.Reasons) > 0 || state.Match.Matched {
		data["matched"] = state.Match.Matched
		data["match_reasons"] = state.Match.Reasons
		if state.Match.Matched {
			data["match_basis"] = commandAuthorizationMatchBasis(state)
		}
	}
	return data
}

func authorizationRequestData(request authorization.Request) map[string]any {
	data := map[string]any{
		"work_package_id":    request.WorkPackageID,
		"work_package_goal":  request.Goal,
		"purpose_patterns":   request.Scope.PurposePatterns,
		"action_classes":     request.Scope.ActionClasses,
		"repositories":       request.Scope.Repositories,
		"risk_ceiling":       request.Scope.RiskCeiling,
		"expires_in_seconds": int64(request.TTL / time.Second),
	}
	if len(request.Scope.Targets) > 0 {
		data["targets"] = request.Scope.Targets
	}
	if len(request.Scope.WritePaths) > 0 {
		data["write_paths"] = request.Scope.WritePaths
	}
	return data
}

func commandAuthorizationMatchBasis(state commandAuthorizationState) []string {
	basis := []string{
		"purpose_within_authorized_patterns",
		"risk_within_ordinary_ceiling",
		"action_classes_within_scope",
		"repositories_within_scope",
	}
	if state.Grant != nil {
		basis = append(basis,
			"status_active_and_not_expired",
			"principal_context_remote_session_workspace_binding_verified",
		)
	} else if state.Request != nil {
		basis = append(basis, "authorization_request_scope_matches_current_action")
	}
	if len(state.Action.Targets) > 0 {
		basis = append(basis, "targets_within_scope")
	}
	if len(state.Action.WritePaths) > 0 {
		basis = append(basis, "write_paths_within_scope")
	}
	if state.Action.Executable != "" {
		basis = append(basis, "trusted_executable_resolved_and_pinned")
	}
	return basis
}

func addCommandAuthorizationRetryArguments(arguments map[string]any, state commandAuthorizationState) {
	if !state.Presented {
		return
	}
	if state.ContextID != "" {
		arguments["authorization_context_id"] = state.ContextID
	}
	if state.GrantID != "" && state.Request == nil {
		arguments["authorization_grant_id"] = state.GrantID
	}
	if state.Request != nil {
		arguments["authorization_request"] = authorizationRequestData(*state.Request)
	}
}

func addCommandAuthorizationData(ctx context.Context, data map[string]any) {
	if state, ok := commandAuthorizationFromContext(ctx); ok {
		data["authorization"] = state.data()
	}
}

func commandExecutionDetailWithAuthorization(
	ctx context.Context,
	purpose, scope, commandDigest string,
	analysis security.CommandAnalysis,
) map[string]any {
	detail := commandExecutionDetail(purpose, scope, commandDigest, analysis)
	addCommandAuthorizationData(ctx, detail)
	return detail
}

func runtimeExecutionDetailWithAuthorization(
	ctx context.Context,
	purpose, scope, commandDigest string,
	spec *ephemeralRuntimeSpec,
	analysis security.CommandAnalysis,
) map[string]any {
	detail := runtimeExecutionDetail(purpose, scope, commandDigest, spec, analysis)
	addCommandAuthorizationData(ctx, detail)
	return detail
}

func combinedCommandPayloadDigest(parts ...string) string {
	nonEmpty := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			nonEmpty = append(nonEmpty, part)
		}
	}
	if len(nonEmpty) == 0 {
		return ""
	}
	if len(nonEmpty) == 1 {
		return nonEmpty[0]
	}
	sum := sha256.Sum256([]byte(strings.Join(nonEmpty, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
