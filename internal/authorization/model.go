// Package authorization owns durable, conversation-scoped work-package grants.
// It deliberately does not make policy decisions: callers must run the normal
// command policy first, then use a grant only to satisfy an ordinary Confirm.
package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	StatusActive     = "active"
	StatusRevoked    = "revoked"
	StatusSuperseded = "superseded"
	StatusExpired    = "expired"

	RiskOrdinary = "ordinary"

	DefaultTTL = 8 * time.Hour
	MinimumTTL = 5 * time.Minute
	MaximumTTL = 24 * time.Hour
)

var (
	ErrNotFound            = errors.New("authorization grant not found")
	ErrInactive            = errors.New("authorization grant is not active")
	ErrScopeExpansion      = errors.New("authorization scope may only be narrowed")
	ErrActiveScopeConflict = errors.New("an equivalent authorization scope is already active under a different confirmation")
)

var validActionClasses = map[string]struct{}{
	"git_read":         {},
	"git_remote_read":  {},
	"git_local_write":  {},
	"git_remote_write": {},
	"github_pr_write":  {},
	"github_pr_merge":  {},
	"git_cleanup":      {},
}

// Scope is the complete machine-enforced boundary of one grant. Repositories
// use canonical identities (workspace:<relative-path> or github:<owner>/<repo>).
// Targets and purpose patterns support the narrow glob syntax accepted by
// path.Match. WritePaths are exact workspace-relative paths or prefix/**.
type Scope struct {
	PurposePatterns []string `json:"purpose_patterns"`
	ActionClasses   []string `json:"action_classes"`
	Repositories    []string `json:"repositories"`
	Targets         []string `json:"targets,omitempty"`
	WritePaths      []string `json:"write_paths,omitempty"`
	RiskCeiling     string   `json:"risk_ceiling"`
}

// Request is the user-visible authorization request frozen into the first
// command confirmation digest.
type Request struct {
	ContextID     string        `json:"authorization_context_id"`
	WorkPackageID string        `json:"work_package_id"`
	Goal          string        `json:"work_package_goal"`
	Scope         Scope         `json:"scope"`
	TTL           time.Duration `json:"-"`
}

// Grant is a durable authorization record. PrincipalID is intentionally not
// exposed by PublicView, but remains part of the persisted and matched identity.
type Grant struct {
	ID                  string     `json:"grant_id"`
	RemoteSessionID     string     `json:"remote_session_id"`
	Workspace           string     `json:"workspace"`
	PrincipalID         string     `json:"-"`
	ContextID           string     `json:"authorization_context_id"`
	WorkPackageID       string     `json:"work_package_id"`
	Goal                string     `json:"work_package_goal"`
	Scope               Scope      `json:"scope"`
	ScopeDigest         string     `json:"scope_digest"`
	GrantDigest         string     `json:"grant_digest"`
	Status              string     `json:"status"`
	SourceRequestID     string     `json:"source_request_id"`
	SourceCommandDigest string     `json:"source_command_digest"`
	SupersedesID        string     `json:"supersedes_grant_id,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevocationReason    string     `json:"revocation_reason,omitempty"`
}

// Action is the conservative machine description of one command. All listed
// classes, repositories, targets and write paths must be covered by the grant.
type Action struct {
	Eligible     bool     `json:"eligible"`
	Risk         string   `json:"risk"`
	Classes      []string `json:"action_classes,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
	Targets      []string `json:"targets,omitempty"`
	WritePaths   []string `json:"write_paths,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Reasons      []string `json:"reasons,omitempty"`
	Executable   string   `json:"-"`
	Arguments    []string `json:"-"`
	Environment  []string `json:"-"`
}

// MatchResult explains exactly why an action did or did not fit a grant.
type MatchResult struct {
	Matched bool     `json:"matched"`
	Reasons []string `json:"reasons,omitempty"`
	Action  Action   `json:"action"`
}

// NormalizeRequest validates and canonicalizes a client authorization request.
func NormalizeRequest(input Request) (Request, error) {
	contextID, err := NormalizeContextID(input.ContextID)
	if err != nil {
		return Request{}, err
	}
	input.ContextID = contextID
	input.WorkPackageID = strings.TrimSpace(input.WorkPackageID)
	input.Goal = strings.TrimSpace(input.Goal)
	if err := validateStableID("work_package_id", input.WorkPackageID); err != nil {
		return Request{}, err
	}
	if input.Goal == "" || len(input.Goal) > 512 {
		return Request{}, errors.New("authorization goal must be 1..512 bytes")
	}
	scope, err := NormalizeScope(input.Scope)
	if err != nil {
		return Request{}, err
	}
	input.Scope = scope
	if input.TTL == 0 {
		input.TTL = DefaultTTL
	}
	if input.TTL < MinimumTTL || input.TTL > MaximumTTL {
		return Request{}, fmt.Errorf("authorization ttl must be between %s and %s", MinimumTTL, MaximumTTL)
	}
	return input, nil
}

// NormalizeContextID validates the explicit conversation/authorization context
// identifier without coupling it to a transport or Remote Session identifier.
func NormalizeContextID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if err := validateStableID("authorization_context_id", value); err != nil {
		return "", err
	}
	return value, nil
}

// NormalizeScope returns a deterministic scope suitable for hashing and SQL
// identity. Empty or unknown dimensions fail closed.
func NormalizeScope(input Scope) (Scope, error) {
	result := Scope{RiskCeiling: strings.ToLower(strings.TrimSpace(input.RiskCeiling))}
	if result.RiskCeiling == "" {
		result.RiskCeiling = RiskOrdinary
	}
	if result.RiskCeiling != RiskOrdinary {
		return Scope{}, errors.New("risk_ceiling must be ordinary")
	}
	for _, value := range input.PurposePatterns {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 256 {
			return Scope{}, errors.New("purpose_patterns entries must be 1..256 bytes")
		}
		if _, err := path.Match(value, strings.Repeat("x", 1)); err != nil {
			return Scope{}, fmt.Errorf("invalid purpose pattern %q: %w", value, err)
		}
		result.PurposePatterns = append(result.PurposePatterns, value)
	}
	if len(result.PurposePatterns) == 0 {
		return Scope{}, errors.New("at least one purpose_pattern is required")
	}
	for _, value := range input.ActionClasses {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := validActionClasses[value]; !ok {
			return Scope{}, fmt.Errorf("unsupported authorization action_class %q", value)
		}
		result.ActionClasses = append(result.ActionClasses, value)
	}
	if len(result.ActionClasses) == 0 {
		return Scope{}, errors.New("at least one action_class is required")
	}
	for _, value := range input.Repositories {
		normalized, err := NormalizeRepository(value)
		if err != nil {
			return Scope{}, err
		}
		result.Repositories = append(result.Repositories, normalized)
	}
	if len(result.Repositories) == 0 {
		return Scope{}, errors.New("at least one repository is required")
	}
	for _, value := range input.Targets {
		normalized, err := normalizeTargetPattern(value)
		if err != nil {
			return Scope{}, err
		}
		result.Targets = append(result.Targets, normalized)
	}
	for _, value := range input.WritePaths {
		normalized, err := NormalizeWritePattern(value)
		if err != nil {
			return Scope{}, err
		}
		result.WritePaths = append(result.WritePaths, normalized)
	}
	result.PurposePatterns = uniqueSorted(result.PurposePatterns)
	result.ActionClasses = uniqueSorted(result.ActionClasses)
	result.Repositories = uniqueSorted(result.Repositories)
	result.Targets = uniqueSorted(result.Targets)
	result.WritePaths = uniqueSorted(result.WritePaths)
	return result, nil
}

func validateStableID(name, value string) error {
	if value == "" || len(value) > 160 {
		return fmt.Errorf("%s must be 1..160 bytes", name)
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._:/#@-", r) {
			continue
		}
		return fmt.Errorf("%s contains unsupported character %q", name, r)
	}
	return nil
}

// NormalizeRepository canonicalizes repository identities without resolving
// network aliases. Runtime command classification resolves git remotes to the
// same canonical form before matching.
func NormalizeRepository(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if strings.HasPrefix(strings.ToLower(value), "github:") {
		repo := strings.TrimSpace(value[len("github:"):])
		repo = strings.TrimSuffix(strings.TrimSuffix(repo, ".git"), "/")
		parts := strings.Split(repo, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(repo, "..") {
			return "", fmt.Errorf("invalid github repository %q", value)
		}
		return "github:" + strings.ToLower(repo), nil
	}
	if strings.HasPrefix(strings.ToLower(value), "workspace:") {
		value = strings.TrimSpace(value[len("workspace:"):])
	}
	cleaned, err := normalizeWorkspaceRelative(value, true)
	if err != nil {
		return "", fmt.Errorf("invalid workspace repository %q: %w", value, err)
	}
	return "workspace:" + cleaned, nil
}

// NormalizeWritePattern accepts exact workspace-relative paths, a directory
// prefix ending in /**, or ./** for the entire registered workspace.
func NormalizeWritePattern(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "." || value == "./**" || value == "**" {
		return "**", nil
	}
	prefix := strings.TrimSuffix(value, "/**")
	isPrefix := prefix != value
	if strings.ContainsAny(prefix, "*?[") {
		return "", fmt.Errorf("write path %q may only use a terminal /** wildcard", value)
	}
	cleaned, err := normalizeWorkspaceRelative(prefix, false)
	if err != nil {
		return "", fmt.Errorf("invalid write path %q: %w", value, err)
	}
	if isPrefix {
		return cleaned + "/**", nil
	}
	return cleaned, nil
}

func normalizeTargetPattern(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || len(value) > 256 {
		return "", errors.New("targets entries must be 1..256 bytes")
	}
	if strings.Contains(value, "..") || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("unsafe target pattern %q", value)
	}
	if _, err := path.Match(value, "target"); err != nil {
		return "", fmt.Errorf("invalid target pattern %q: %w", value, err)
	}
	return value, nil
}

func normalizeWorkspaceRelative(value string, allowDot bool) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || value == "." {
		if allowDot {
			return ".", nil
		}
		return "", errors.New("path is required")
	}
	if strings.HasPrefix(value, "/") || len(value) >= 2 && value[1] == ':' {
		return "", errors.New("absolute paths are not allowed")
	}
	cleaned := path.Clean(value)
	if cleaned == "." && allowDot {
		return ".", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return "", errors.New("path escape is not allowed")
	}
	if strings.ContainsAny(cleaned, "\r\n\x00") {
		return "", errors.New("control characters are not allowed")
	}
	return cleaned, nil
}

// RequestDigest is included in the pending command digest so a confirmed retry
// cannot silently substitute a wider work package.
func RequestDigest(request Request) (string, error) {
	normalized, err := NormalizeRequest(request)
	if err != nil {
		return "", err
	}
	payload := struct {
		ContextID     string `json:"authorization_context_id"`
		WorkPackageID string `json:"work_package_id"`
		Goal          string `json:"work_package_goal"`
		Scope         Scope  `json:"scope"`
		TTLMillis     int64  `json:"ttl_ms"`
	}{normalized.ContextID, normalized.WorkPackageID, normalized.Goal, normalized.Scope, normalized.TTL.Milliseconds()}
	return digestJSON(payload)
}

func ScopeDigest(scope Scope) (string, error) {
	normalized, err := NormalizeScope(scope)
	if err != nil {
		return "", err
	}
	return digestJSON(normalized)
}

func ComputeGrantDigest(grant Grant) string {
	payload := struct {
		ID                  string `json:"id"`
		RemoteSessionID     string `json:"remote_session_id"`
		Workspace           string `json:"workspace"`
		PrincipalID         string `json:"principal_id"`
		ContextID           string `json:"authorization_context_id"`
		WorkPackageID       string `json:"work_package_id"`
		Goal                string `json:"work_package_goal"`
		ScopeDigest         string `json:"scope_digest"`
		SourceCommandDigest string `json:"source_command_digest"`
		CreatedAt           int64  `json:"created_at"`
		ExpiresAt           int64  `json:"expires_at"`
	}{grant.ID, grant.RemoteSessionID, grant.Workspace, grant.PrincipalID, grant.ContextID, grant.WorkPackageID, grant.Goal, grant.ScopeDigest, grant.SourceCommandDigest, grant.CreatedAt.UnixMilli(), grant.ExpiresAt.UnixMilli()}
	digest, _ := digestJSON(payload)
	return digest
}

func digestJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Match evaluates every current command dimension against an active grant.
func Match(grant Grant, purpose string, action Action, now time.Time) MatchResult {
	result := MatchResult{Action: canonicalAction(action)}
	if grant.Status != StatusActive {
		result.Reasons = append(result.Reasons, "grant_status:"+grant.Status)
	}
	if !grant.ExpiresAt.After(now.UTC()) {
		result.Reasons = append(result.Reasons, "grant_expired")
	}
	if !result.Action.Eligible {
		if len(result.Action.Reasons) == 0 {
			result.Reasons = append(result.Reasons, "command_not_grant_eligible")
		} else {
			for _, reason := range result.Action.Reasons {
				result.Reasons = append(result.Reasons, "command:"+reason)
			}
		}
	}
	if result.Action.Risk != RiskOrdinary {
		result.Reasons = append(result.Reasons, "risk_exceeds_ordinary:"+result.Action.Risk)
	}
	if !matchesAny(strings.ToLower(strings.TrimSpace(purpose)), grant.Scope.PurposePatterns) {
		result.Reasons = append(result.Reasons, "purpose_out_of_scope")
	}
	for _, class := range result.Action.Classes {
		if !contains(grant.Scope.ActionClasses, class) {
			result.Reasons = append(result.Reasons, "action_class_out_of_scope:"+class)
		}
	}
	for _, repository := range result.Action.Repositories {
		if !contains(grant.Scope.Repositories, repository) {
			result.Reasons = append(result.Reasons, "repository_out_of_scope:"+repository)
		}
	}
	for _, target := range result.Action.Targets {
		if !matchesAny(target, grant.Scope.Targets) {
			result.Reasons = append(result.Reasons, "target_out_of_scope:"+target)
		}
	}
	for _, writePath := range result.Action.WritePaths {
		if !writePathCovered(writePath, grant.Scope.WritePaths) {
			result.Reasons = append(result.Reasons, "write_path_out_of_scope:"+writePath)
		}
	}
	result.Reasons = uniqueSortedText(result.Reasons)
	result.Matched = len(result.Reasons) == 0
	return result
}

// IsStrictSubset validates a proposed scope-only narrow operation. Pattern
// subset checks are intentionally conservative: equality, an old catch-all,
// or a deeper path below an old terminal /** prefix are accepted; ambiguous
// glob algebra is rejected rather than risking expansion.
func IsStrictSubset(next, current Scope) (bool, error) {
	changed, err := isScopeSubset(next, current)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, errors.New("authorization narrow request must reduce at least one boundary")
	}
	return true, nil
}

// isScopeSubset proves that next does not expand current and reports whether
// any scope boundary changed. Store.Narrow also uses it so an otherwise equal
// scope may be paired with a strictly earlier expiry.
func isScopeSubset(next, current Scope) (bool, error) {
	next, err := NormalizeScope(next)
	if err != nil {
		return false, err
	}
	current, err = NormalizeScope(current)
	if err != nil {
		return false, err
	}
	if next.RiskCeiling != current.RiskCeiling {
		return false, fmt.Errorf("%w: risk_ceiling", ErrScopeExpansion)
	}
	if !allContained(next.ActionClasses, current.ActionClasses) {
		return false, fmt.Errorf("%w: action_classes", ErrScopeExpansion)
	}
	if !allContained(next.Repositories, current.Repositories) {
		return false, fmt.Errorf("%w: repositories", ErrScopeExpansion)
	}
	if !patternsCovered(next.PurposePatterns, current.PurposePatterns, false) {
		return false, fmt.Errorf("%w: purpose_patterns", ErrScopeExpansion)
	}
	if !patternsCovered(next.Targets, current.Targets, false) {
		return false, fmt.Errorf("%w: targets", ErrScopeExpansion)
	}
	if !patternsCovered(next.WritePaths, current.WritePaths, true) {
		return false, fmt.Errorf("%w: write_paths", ErrScopeExpansion)
	}
	nextDigest, _ := ScopeDigest(next)
	currentDigest, _ := ScopeDigest(current)
	return nextDigest != currentDigest, nil
}

func canonicalAction(action Action) Action {
	action.Risk = strings.ToLower(strings.TrimSpace(action.Risk))
	if action.Risk == "" {
		action.Risk = RiskOrdinary
	}
	action.Classes = uniqueSorted(action.Classes)
	action.Repositories = uniqueSorted(action.Repositories)
	action.Targets = uniqueSorted(action.Targets)
	action.WritePaths = uniqueSortedExact(action.WritePaths)
	action.Reasons = uniqueSortedText(action.Reasons)
	return action
}

func allContained(values, allowed []string) bool {
	for _, value := range values {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}

func patternsCovered(values, allowed []string, writePaths bool) bool {
	for _, value := range values {
		covered := false
		for _, candidate := range allowed {
			if value == candidate {
				covered = true
				break
			}
			if writePaths {
				if candidate == "**" {
					covered = true
					break
				}
				if strings.HasSuffix(candidate, "/**") {
					prefix := strings.TrimSuffix(candidate, "/**")
					valuePrefix := strings.TrimSuffix(value, "/**")
					if valuePrefix == prefix || strings.HasPrefix(valuePrefix, prefix+"/") {
						covered = true
						break
					}
				}
				continue
			}

			// path.Match wildcards never cross '/'. A catch-all therefore only
			// proves coverage for a proposed pattern that also has no slash.
			if (candidate == "*" || candidate == "**") && !strings.Contains(value, "/") {
				covered = true
				break
			}
			// A literal proposed value is a singleton set, so matching it against
			// the current pattern proves subset. For two non-identical globs we
			// reject instead of attempting unsafe glob algebra.
			if !strings.ContainsAny(value, "*?[") {
				matched, err := path.Match(candidate, value)
				if err == nil && matched {
					covered = true
					break
				}
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func writePathCovered(value string, patterns []string) bool {
	value = strings.ReplaceAll(value, "\\", "/")
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	for _, pattern := range patterns {
		if pattern == "**" || pattern == value {
			return true
		}
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			if value == prefix || strings.HasPrefix(value, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func matchesAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := path.Match(pattern, value)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueSortedText(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueSortedExact(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ReplaceAll(value, "\\", "/")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// PublicView is safe for tool responses and audit details.
func PublicView(grant Grant) map[string]any {
	view := map[string]any{
		"grant_id":                 grant.ID,
		"remote_session_id":        grant.RemoteSessionID,
		"workspace":                grant.Workspace,
		"authorization_context_id": grant.ContextID,
		"work_package_id":          grant.WorkPackageID,
		"work_package_goal":        grant.Goal,
		"scope":                    grant.Scope,
		"scope_digest":             grant.ScopeDigest,
		"grant_digest":             grant.GrantDigest,
		"status":                   grant.Status,
		"source_request_id":        grant.SourceRequestID,
		"source_command_digest":    grant.SourceCommandDigest,
		"supersedes_grant_id":      grant.SupersedesID,
		"created_at":               grant.CreatedAt.Format(time.RFC3339Nano),
		"expires_at":               grant.ExpiresAt.Format(time.RFC3339Nano),
		"updated_at":               grant.UpdatedAt.Format(time.RFC3339Nano),
		"revocation_reason":        grant.RevocationReason,
	}
	if grant.RevokedAt != nil {
		view["revoked_at"] = grant.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	return view
}
