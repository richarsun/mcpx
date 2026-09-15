package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"mcpx/internal/authorization"
)

type commandAuthorizationContextKey struct{}

type commandAuthorizationState struct {
	Presented     bool
	ContextID     string
	GrantID       string
	Request       *authorization.Request
	RequestDigest string
	Action        authorization.Action
	Match         authorization.MatchResult
	Grant         *authorization.Grant
	Decision      string
}

func withCommandAuthorization(ctx context.Context, state commandAuthorizationState) context.Context {
	return context.WithValue(ctx, commandAuthorizationContextKey{}, state)
}

func commandAuthorizationFromContext(ctx context.Context) (commandAuthorizationState, bool) {
	state, ok := ctx.Value(commandAuthorizationContextKey{}).(commandAuthorizationState)
	return state, ok && state.Presented
}

func deniedCommandAuthorizationState(payload map[string]any) commandAuthorizationState {
	state := commandAuthorizationState{
		ContextID: strings.TrimSpace(stringPayload(payload, "authorization_context_id")),
		GrantID:   strings.TrimSpace(stringPayload(payload, "authorization_grant_id")),
		Decision:  "denied_by_command_policy",
	}
	_, requestPresented := payload["authorization_request"]
	state.Presented = state.ContextID != "" || state.GrantID != "" || requestPresented
	return state
}

func parseCommandAuthorization(payload map[string]any) (commandAuthorizationState, error) {
	state := commandAuthorizationState{
		ContextID: strings.TrimSpace(stringPayload(payload, "authorization_context_id")),
		GrantID:   strings.TrimSpace(stringPayload(payload, "authorization_grant_id")),
	}
	rawRequest, requestPresented := payload["authorization_request"]
	state.Presented = state.ContextID != "" || state.GrantID != "" || requestPresented
	if !state.Presented {
		return state, nil
	}
	if len(state.ContextID) > 160 {
		return state, errors.New("authorization_context_id exceeds 160 bytes")
	}
	if len(state.GrantID) > 200 {
		return state, errors.New("authorization_grant_id exceeds 200 bytes")
	}
	if state.GrantID != "" && requestPresented {
		return state, errors.New("authorization_grant_id and authorization_request are mutually exclusive")
	}
	if (state.GrantID != "" || requestPresented) && state.ContextID == "" {
		return state, errors.New("authorization_context_id is required with authorization_grant_id or authorization_request")
	}
	if !requestPresented {
		state.Decision = "context_only"
		return state, nil
	}
	requestMap, ok := rawRequest.(map[string]any)
	if !ok || requestMap == nil {
		return state, errors.New("authorization_request must be an object")
	}
	allowed := map[string]bool{
		"work_package_id":    true,
		"work_package_goal":  true,
		"purpose_patterns":   true,
		"action_classes":     true,
		"repositories":       true,
		"targets":            true,
		"write_paths":        true,
		"risk_ceiling":       true,
		"expires_in_seconds": true,
	}
	for key := range requestMap {
		if !allowed[key] {
			return state, fmt.Errorf("authorization_request contains unsupported field %q", key)
		}
	}
	scope, err := authorizationScopeFromMap(requestMap, "authorization_request")
	if err != nil {
		return state, err
	}
	ttl, err := authorizationTTL(requestMap, "expires_in_seconds")
	if err != nil {
		return state, err
	}
	request, err := authorization.NormalizeRequest(authorization.Request{
		ContextID:     state.ContextID,
		WorkPackageID: strings.TrimSpace(stringPayload(requestMap, "work_package_id")),
		Goal:          strings.TrimSpace(stringPayload(requestMap, "work_package_goal")),
		Scope:         scope,
		TTL:           ttl,
	})
	if err != nil {
		return state, err
	}
	requestDigest, err := authorization.RequestDigest(request)
	if err != nil {
		return state, err
	}
	state.Request = &request
	state.RequestDigest = requestDigest
	state.Decision = "authorization_request_pending"
	return state, nil
}

func authorizationScopeFromMap(payload map[string]any, field string) (authorization.Scope, error) {
	purposePatterns, err := authorizationStringSlice(payload, field, "purpose_patterns", true)
	if err != nil {
		return authorization.Scope{}, err
	}
	actionClasses, err := authorizationStringSlice(payload, field, "action_classes", true)
	if err != nil {
		return authorization.Scope{}, err
	}
	repositories, err := authorizationStringSlice(payload, field, "repositories", true)
	if err != nil {
		return authorization.Scope{}, err
	}
	targets, err := authorizationStringSlice(payload, field, "targets", false)
	if err != nil {
		return authorization.Scope{}, err
	}
	writePaths, err := authorizationStringSlice(payload, field, "write_paths", false)
	if err != nil {
		return authorization.Scope{}, err
	}
	return authorization.NormalizeScope(authorization.Scope{
		PurposePatterns: purposePatterns,
		ActionClasses:   actionClasses,
		Repositories:    repositories,
		Targets:         targets,
		WritePaths:      writePaths,
		RiskCeiling:     strings.TrimSpace(stringPayload(payload, "risk_ceiling")),
	})
}

func authorizationStringSlice(payload map[string]any, field, key string, required bool) ([]string, error) {
	raw, exists := payload[key]
	if !exists {
		if required {
			return nil, fmt.Errorf("%s.%s is required", field, key)
		}
		return nil, nil
	}
	var values []string
	switch typed := raw.(type) {
	case []string:
		values = append(values, typed...)
	case []any:
		for index, item := range typed {
			value, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s.%s[%d] must be a string", field, key, index)
			}
			values = append(values, value)
		}
	default:
		return nil, fmt.Errorf("%s.%s must be an array of strings", field, key)
	}
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%s.%s must not be empty", field, key)
	}
	return values, nil
}

func authorizationTTL(payload map[string]any, key string) (time.Duration, error) {
	raw, exists := payload[key]
	if !exists || raw == nil {
		return 0, nil
	}
	var seconds int64
	switch typed := raw.(type) {
	case int:
		seconds = int64(typed)
	case int32:
		seconds = int64(typed)
	case int64:
		seconds = typed
	case float64:
		if math.Trunc(typed) != typed || typed > math.MaxInt64 || typed < math.MinInt64 {
			return 0, fmt.Errorf("%s must be an integer number of seconds", key)
		}
		seconds = int64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer number of seconds", key)
		}
		seconds = parsed
	default:
		return 0, fmt.Errorf("%s must be an integer number of seconds", key)
	}
	minimum := int64(authorization.MinimumTTL / time.Second)
	maximum := int64(authorization.MaximumTTL / time.Second)
	if seconds < minimum || seconds > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minimum, maximum)
	}
	return time.Duration(seconds) * time.Second, nil
}
