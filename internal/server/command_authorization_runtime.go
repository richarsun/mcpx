package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"mcpx/internal/audit"
	"mcpx/internal/auth"
	"mcpx/internal/authorization"
	"mcpx/internal/envelope"
	"mcpx/internal/remotesession"
	"mcpx/internal/security"
)

func (r *Runtime) evaluateCommandAuthorization(
	ctx context.Context,
	payload map[string]any,
	principal auth.Principal,
	remote remotesession.Session,
	command, purpose string,
	analysis security.CommandAnalysis,
) (commandAuthorizationState, error) {
	state, err := parseCommandAuthorization(payload)
	if err != nil || !state.Presented {
		return state, err
	}
	if state.Request == nil && state.GrantID == "" {
		return state, nil
	}

	segments := make([]string, 0, len(analysis.Segments))
	for _, segment := range analysis.Segments {
		segments = append(segments, segment.Command)
	}
	if len(segments) == 0 {
		segments = append(segments, command)
	}
	state.Action = authorization.ClassifyCommand(ctx, remote.WorkspacePath, segments)
	now := time.Now().UTC()

	if state.Request != nil {
		candidate := authorization.Grant{
			Status:    authorization.StatusActive,
			Scope:     state.Request.Scope,
			ExpiresAt: now.Add(state.Request.TTL),
		}
		state.Match = authorization.Match(candidate, purpose, state.Action, now)
		if !state.Match.Matched {
			return state, fmt.Errorf(
				"authorization_request does not cover the initiating command: %s",
				strings.Join(state.Match.Reasons, ", "),
			)
		}
		return state, nil
	}
	if r.authorizations == nil {
		return state, errors.New("authorization grant store is unavailable")
	}
	grant, getErr := r.authorizations.GetBound(ctx, authorization.BoundIdentity{
		RemoteSessionID: remote.ID,
		Workspace:       remote.WorkspaceName,
		PrincipalID:     principal.ID,
		ContextID:       state.ContextID,
	}, state.GrantID, now)
	if getErr != nil {
		if !errors.Is(getErr, authorization.ErrNotFound) {
			return state, fmt.Errorf("load authorization grant: %w", getErr)
		}
		state.Decision = "grant_unavailable"
		state.Match = authorization.MatchResult{
			Matched: false,
			Action:  state.Action,
			Reasons: []string{"grant_not_found_for_current_principal_context_session_workspace"},
		}
		return state, nil
	}
	state.Grant = &grant
	state.GrantID = grant.ID
	state.Match = authorization.Match(grant, purpose, state.Action, now)
	if state.Match.Matched {
		state.Decision = "grant_matched"
	} else {
		state.Decision = "grant_scope_mismatch"
	}
	return state, nil
}

func (r *Runtime) activateCommandAuthorization(
	ctx context.Context,
	envReq envelope.Request,
	principal auth.Principal,
	remote remotesession.Session,
	command, commandDigest string,
	state commandAuthorizationState,
) (commandAuthorizationState, error) {
	if state.Request == nil {
		return state, nil
	}
	if r.authorizations == nil {
		return state, errors.New("authorization grant store is unavailable")
	}
	grant, reused, err := r.authorizations.CreateOrReuse(ctx, authorization.CreateInput{
		RemoteSessionID:     remote.ID,
		Workspace:           remote.WorkspaceName,
		PrincipalID:         principal.ID,
		SourceRequestID:     envReq.RequestID,
		SourceCommandDigest: commandDigest,
		Request:             *state.Request,
		Now:                 time.Now().UTC(),
	})
	if err != nil {
		return state, err
	}
	state.Grant = &grant
	state.GrantID = grant.ID
	state.ContextID = grant.ContextID
	state.Match = authorization.Match(grant, envReq.Intent, state.Action, time.Now().UTC())
	if !state.Match.Matched {
		if !reused {
			_, _ = r.authorizations.Revoke(ctx, authorization.BoundIdentity{
				RemoteSessionID: remote.ID,
				Workspace:       remote.WorkspaceName,
				PrincipalID:     principal.ID,
				ContextID:       grant.ContextID,
			}, grant.ID, "created grant failed post-confirmation scope validation", time.Now().UTC())
		}
		return state, errors.New("created authorization grant no longer matches the confirmed command")
	}
	if reused {
		state.Decision = "grant_reused_after_confirmation"
	} else {
		state.Decision = "grant_created"
	}
	detail := map[string]any{
		"command_digest": commandDigest,
		"authorization":  state.data(),
	}
	if err := r.writeAudit(audit.Event{
		RequestID:       envReq.RequestID,
		RemoteSessionID: remote.ID,
		Workspace:       remote.WorkspaceName,
		Tool:            "execute",
		Command:         command,
		Status:          state.Decision,
		Detail:          detail,
	}); err != nil {
		if !reused {
			_, _ = r.authorizations.Revoke(ctx, authorization.BoundIdentity{
				RemoteSessionID: remote.ID,
				Workspace:       remote.WorkspaceName,
				PrincipalID:     principal.ID,
				ContextID:       grant.ContextID,
			}, grant.ID, "authorization audit persistence failed", time.Now().UTC())
		}
		return state, fmt.Errorf("persist authorization audit: %w", err)
	}
	return state, nil
}

func (state commandAuthorizationState) matchedGrant() bool {
	return state.Grant != nil && state.Match.Matched
}
