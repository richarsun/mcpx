package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/audit"
	"mcpx/internal/authorization"
	"mcpx/internal/envelope"
)

func (r *Runtime) toolAuthorizationLifecycle(ctx context.Context, req *mcp.CallToolRequest, action string) (*mcp.CallToolResult, error) {
	mutating := action != "authorization_list"
	envReq, principal, remote, fail := r.changeRequest(ctx, req, mutating)
	if fail != nil {
		return fail, nil
	}
	contextID, err := authorization.NormalizeContextID(stringPayload(envReq.Payload, "authorization_context_id"))
	if err != nil {
		return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "bad_request", err.Error())
	}
	identity := authorization.BoundIdentity{
		RemoteSessionID: remote.ID,
		Workspace:       remote.WorkspaceName,
		PrincipalID:     principal.ID,
		ContextID:       contextID,
	}
	now := time.Now().UTC()

	switch action {
	case "authorization_list":
		includeInactive := boolPayload(envReq.Payload, "authorization_include_inactive")
		grants, listErr := r.authorizations.List(ctx, identity, includeInactive, now)
		if listErr != nil {
			return r.authorizationLifecycleError(ctx, envReq, remote.ID, remote.WorkspaceName, listErr)
		}
		views := authorizationPublicViews(grants)
		if auditErr := r.writeAudit(audit.Event{
			RequestID: envReq.RequestID, RemoteSessionID: remote.ID, Workspace: remote.WorkspaceName,
			Tool: "session", Status: "authorization_listed",
			Detail: map[string]any{
				"authorization_context_id": contextID,
				"include_inactive":         includeInactive,
				"grant_count":              len(views),
			},
		}); auditErr != nil {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "audit_write_failed", "authorization list audit could not be persisted")
		}
		return r.remoteResult(envReq, remote.ID, remote.WorkspaceName, map[string]any{
			"authorization_context_id": contextID,
			"authorization_grants":     views,
			"count":                    len(views),
			"include_inactive":         includeInactive,
		})

	case "authorization_revoke":
		grantID := strings.TrimSpace(stringPayload(envReq.Payload, "authorization_grant_id"))
		if grantID == "" {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "bad_request", "authorization_grant_id is required")
		}
		reason := strings.TrimSpace(stringPayload(envReq.Payload, "authorization_reason"))
		if reason == "" {
			reason = strings.TrimSpace(envReq.Intent)
		}
		grant, revokeErr := r.authorizations.Revoke(ctx, identity, grantID, reason, now)
		if revokeErr != nil {
			return r.authorizationLifecycleError(ctx, envReq, remote.ID, remote.WorkspaceName, revokeErr)
		}
		view := authorization.PublicView(grant)
		if auditErr := r.writeAudit(audit.Event{
			RequestID: envReq.RequestID, RemoteSessionID: remote.ID, Workspace: remote.WorkspaceName,
			Tool: "session", Status: "authorization_revoked",
			Detail: map[string]any{
				"authorization_context_id": contextID,
				"authorization_grant":      view,
				"reason":                   reason,
			},
		}); auditErr != nil {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "audit_write_failed", "authorization revocation audit could not be persisted")
		}
		return r.remoteResult(envReq, remote.ID, remote.WorkspaceName, map[string]any{
			"authorization_context_id": contextID,
			"authorization_grant":      view,
			"revoked":                  true,
		})

	case "authorization_narrow":
		grantID := strings.TrimSpace(stringPayload(envReq.Payload, "authorization_grant_id"))
		if grantID == "" {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "bad_request", "authorization_grant_id is required")
		}
		rawScope, ok := envReq.Payload["authorization_scope"].(map[string]any)
		if !ok || rawScope == nil {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "bad_request", "authorization_scope is required and must be an object")
		}
		for key := range rawScope {
			switch key {
			case "purpose_patterns", "action_classes", "repositories", "targets", "write_paths", "risk_ceiling":
			default:
				return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "bad_request", fmt.Sprintf("authorization_scope contains unsupported field %q", key))
			}
		}
		scope, scopeErr := authorizationScopeFromMap(rawScope, "authorization_scope")
		if scopeErr != nil {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "bad_request", scopeErr.Error())
		}
		expiresAt, expiresErr := authorizationLifecycleExpiry(envReq.Payload)
		if expiresErr != nil {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "bad_request", expiresErr.Error())
		}
		reason := strings.TrimSpace(stringPayload(envReq.Payload, "authorization_reason"))
		if reason == "" {
			reason = strings.TrimSpace(envReq.Intent)
		}
		sourceDigest := authorizationLifecycleDigest(action, contextID, grantID, scope, expiresAt)
		grant, narrowErr := r.authorizations.Narrow(ctx, authorization.NarrowInput{
			Identity:            identity,
			GrantID:             grantID,
			Scope:               scope,
			ExpiresAt:           expiresAt,
			SourceRequestID:     envReq.RequestID,
			SourceCommandDigest: sourceDigest,
			Reason:              reason,
			Now:                 now,
		})
		if narrowErr != nil {
			return r.authorizationLifecycleError(ctx, envReq, remote.ID, remote.WorkspaceName, narrowErr)
		}
		view := authorization.PublicView(grant)
		if auditErr := r.writeAudit(audit.Event{
			RequestID: envReq.RequestID, RemoteSessionID: remote.ID, Workspace: remote.WorkspaceName,
			Tool: "session", Status: "authorization_narrowed",
			Detail: map[string]any{
				"authorization_context_id": contextID,
				"authorization_grant":      view,
				"source_grant_id":          grantID,
				"source_action_digest":     sourceDigest,
				"reason":                   reason,
			},
		}); auditErr != nil {
			return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "audit_write_failed", "authorization narrow audit could not be persisted")
		}
		return r.remoteResult(envReq, remote.ID, remote.WorkspaceName, map[string]any{
			"authorization_context_id": contextID,
			"authorization_grant":      view,
			"superseded_grant_id":      grantID,
			"narrowed":                 true,
		})
	default:
		return r.terminalErrorForContext(ctx, envReq, remote.ID, remote.WorkspaceName, "invalid_action", fmt.Sprintf("session does not support action %q", action))
	}
}

func authorizationPublicViews(grants []authorization.Grant) []map[string]any {
	views := make([]map[string]any, 0, len(grants))
	for _, grant := range grants {
		views = append(views, authorization.PublicView(grant))
	}
	return views
}

func authorizationLifecycleExpiry(payload map[string]any) (time.Time, error) {
	raw := strings.TrimSpace(stringPayload(payload, "authorization_expires_at"))
	if raw == "" {
		return time.Time{}, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("authorization_expires_at must be RFC3339: %w", err)
	}
	return value.UTC(), nil
}

func authorizationLifecycleDigest(action, contextID, grantID string, scope authorization.Scope, expiresAt time.Time) string {
	scopeDigest, _ := authorization.ScopeDigest(scope)
	value := strings.Join([]string{action, contextID, grantID, scopeDigest, expiresAt.UTC().Format(time.RFC3339Nano)}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", digest[:])
}

func (r *Runtime) authorizationLifecycleError(ctx context.Context, envReq envelope.Request, remoteID, workspace string, err error) (*mcp.CallToolResult, error) {
	code := "authorization_store_error"
	switch {
	case errors.Is(err, authorization.ErrNotFound):
		code = "authorization_not_found"
	case errors.Is(err, authorization.ErrInactive):
		code = "authorization_inactive"
	case errors.Is(err, authorization.ErrScopeExpansion):
		code = "authorization_scope_expansion"
	case errors.Is(err, authorization.ErrActiveScopeConflict):
		code = "authorization_active_scope_conflict"
	}
	return r.terminalErrorForContext(ctx, envReq, remoteID, workspace, code, err.Error())
}
