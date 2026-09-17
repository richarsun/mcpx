package authorization

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CreateInput binds one normalized request to the runtime identity that
// received the user's semantic confirmation.
type CreateInput struct {
	RemoteSessionID     string
	Workspace           string
	PrincipalID         string
	SourceRequestID     string
	SourceCommandDigest string
	Request             Request
	Now                 time.Time
}

// BoundIdentity prevents grant lookup or lifecycle operations from crossing a
// principal, conversation, Remote Session or Workspace boundary.
type BoundIdentity struct {
	RemoteSessionID string
	Workspace       string
	PrincipalID     string
	ContextID       string
}

// NarrowInput creates a new grant that is a strict subset of an active grant.
type NarrowInput struct {
	Identity            BoundIdentity
	GrantID             string
	Scope               Scope
	ExpiresAt           time.Time
	SourceRequestID     string
	SourceCommandDigest string
	Reason              string
	Now                 time.Time
}

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// CreateOrReuse atomically returns an existing equivalent active grant or
// inserts one. The active-scope unique index closes reconnect/concurrent races.
func (s *Store) CreateOrReuse(ctx context.Context, input CreateInput) (Grant, bool, error) {
	if s == nil || s.db == nil {
		return Grant{}, false, errors.New("authorization store database is required")
	}
	request, err := NormalizeRequest(input.Request)
	if err != nil {
		return Grant{}, false, err
	}
	if err := validateCreateInput(input, request); err != nil {
		return Grant{}, false, err
	}
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	scopeDigest, err := ScopeDigest(request.Scope)
	if err != nil {
		return Grant{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, false, err
	}
	defer tx.Rollback()
	if err := expireActiveTx(ctx, tx, now); err != nil {
		return Grant{}, false, err
	}
	if existing, findErr := findActiveScopeTx(ctx, tx, input, request, scopeDigest, now); findErr == nil {
		if existing.SourceCommandDigest != strings.TrimSpace(input.SourceCommandDigest) {
			return Grant{}, false, fmt.Errorf("%w; revoke or narrow the existing grant before authorizing a different TTL or boundary", ErrActiveScopeConflict)
		}
		if err := tx.Commit(); err != nil {
			return Grant{}, false, err
		}
		return existing, true, nil
	} else if !errors.Is(findErr, ErrNotFound) {
		return Grant{}, false, findErr
	}

	grant := Grant{
		ID:                  "grant_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RemoteSessionID:     strings.TrimSpace(input.RemoteSessionID),
		Workspace:           strings.TrimSpace(input.Workspace),
		PrincipalID:         strings.TrimSpace(input.PrincipalID),
		ContextID:           request.ContextID,
		WorkPackageID:       request.WorkPackageID,
		Goal:                request.Goal,
		Scope:               request.Scope,
		ScopeDigest:         scopeDigest,
		Status:              StatusActive,
		SourceRequestID:     strings.TrimSpace(input.SourceRequestID),
		SourceCommandDigest: strings.TrimSpace(input.SourceCommandDigest),
		CreatedAt:           now,
		ExpiresAt:           now.Add(request.TTL),
		UpdatedAt:           now,
	}
	grant.GrantDigest = ComputeGrantDigest(grant)
	if err := insertGrantTx(ctx, tx, grant); err != nil {
		// A concurrent exact retry may win the unique active-scope index. Only
		// the same semantic confirmation digest may recover that grant; a
		// different TTL or authorization boundary must fail explicitly.
		if existing, findErr := findActiveScopeTx(ctx, tx, input, request, scopeDigest, now); findErr == nil {
			if existing.SourceCommandDigest != strings.TrimSpace(input.SourceCommandDigest) {
				return Grant{}, false, fmt.Errorf("%w; revoke or narrow the existing grant before authorizing a different TTL or boundary", ErrActiveScopeConflict)
			}
			if commitErr := tx.Commit(); commitErr != nil {
				return Grant{}, false, commitErr
			}
			return existing, true, nil
		}
		return Grant{}, false, fmt.Errorf("persist authorization grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Grant{}, false, err
	}
	return grant, false, nil
}

func validateCreateInput(input CreateInput, request Request) error {
	for name, value := range map[string]string{
		"remote_session_id":     input.RemoteSessionID,
		"workspace":             input.Workspace,
		"principal_id":          input.PrincipalID,
		"source_request_id":     input.SourceRequestID,
		"source_command_digest": input.SourceCommandDigest,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if request.ContextID == "" || request.WorkPackageID == "" {
		return errors.New("authorization request identity is required")
	}
	return nil
}

// GetBound returns a grant only when all non-secret identity dimensions match.
// It returns ErrNotFound for an identity mismatch to avoid cross-context leaks.
func (s *Store) GetBound(ctx context.Context, identity BoundIdentity, grantID string, now time.Time) (Grant, error) {
	if s == nil || s.db == nil {
		return Grant{}, errors.New("authorization store database is required")
	}
	now = normalizedNow(now)
	if err := s.expireActive(ctx, now); err != nil {
		return Grant{}, err
	}
	grant, err := s.get(ctx, grantID)
	if err != nil {
		return Grant{}, err
	}
	if !sameIdentity(grant, identity) {
		return Grant{}, ErrNotFound
	}
	return grant, nil
}

// List returns grants for exactly one principal/session/workspace/context.
func (s *Store) List(ctx context.Context, identity BoundIdentity, includeInactive bool, now time.Time) ([]Grant, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("authorization store database is required")
	}
	now = normalizedNow(now)
	if err := s.expireActive(ctx, now); err != nil {
		return nil, err
	}
	query := `SELECT ` + grantColumns + ` FROM authorization_grants
		WHERE remote_session_id = ? AND workspace_name = ? AND principal_id = ? AND authorization_context_id = ?`
	arguments := []any{identity.RemoteSessionID, identity.Workspace, identity.PrincipalID, identity.ContextID}
	if !includeInactive {
		query += ` AND status = 'active'`
	}
	query += ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Grant, 0)
	for rows.Next() {
		grant, scanErr := scanGrant(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, grant)
	}
	return result, rows.Err()
}

// Revoke is idempotent for an already-revoked grant and immediate for all
// subsequent command matches because Runtime never caches grant status.
func (s *Store) Revoke(ctx context.Context, identity BoundIdentity, grantID, reason string, now time.Time) (Grant, error) {
	if s == nil || s.db == nil {
		return Grant{}, errors.New("authorization store database is required")
	}
	now = normalizedNow(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, err
	}
	defer tx.Rollback()
	if err := expireActiveTx(ctx, tx, now); err != nil {
		return Grant{}, err
	}
	grant, err := getGrantTx(ctx, tx, grantID)
	if err != nil || !sameIdentity(grant, identity) {
		if err == nil {
			err = ErrNotFound
		}
		return Grant{}, err
	}
	if grant.Status == StatusRevoked {
		if err := tx.Commit(); err != nil {
			return Grant{}, err
		}
		return grant, nil
	}
	if grant.Status != StatusActive {
		return Grant{}, ErrInactive
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "user revoked authorization"
	}
	if len(reason) > 512 {
		return Grant{}, errors.New("revocation reason must be at most 512 bytes")
	}
	result, err := tx.ExecContext(ctx, `UPDATE authorization_grants
		SET status = 'revoked', revoked_at = ?, updated_at = ?, revocation_reason = ?
		WHERE id = ? AND status = 'active'`, now.UnixMilli(), now.UnixMilli(), reason, grant.ID)
	if err != nil {
		return Grant{}, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return Grant{}, ErrInactive
	}
	grant.Status = StatusRevoked
	grant.UpdatedAt = now
	grant.RevokedAt = &now
	grant.RevocationReason = reason
	if err := tx.Commit(); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// Narrow atomically supersedes the old grant and creates a new stable identity
// with a strictly narrower scope and/or an earlier expiry. It cannot lengthen
// the original expiry.
func (s *Store) Narrow(ctx context.Context, input NarrowInput) (Grant, error) {
	if s == nil || s.db == nil {
		return Grant{}, errors.New("authorization store database is required")
	}
	now := normalizedNow(input.Now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, err
	}
	defer tx.Rollback()
	if err := expireActiveTx(ctx, tx, now); err != nil {
		return Grant{}, err
	}
	current, err := getGrantTx(ctx, tx, strings.TrimSpace(input.GrantID))
	if err != nil || !sameIdentity(current, input.Identity) {
		if err == nil {
			err = ErrNotFound
		}
		return Grant{}, err
	}
	nextScope, err := NormalizeScope(input.Scope)
	if err != nil {
		return Grant{}, err
	}
	expiresAt := input.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		expiresAt = current.ExpiresAt
	}
	scopeDigest, err := ScopeDigest(nextScope)
	if err != nil {
		return Grant{}, err
	}
	if current.Status == StatusSuperseded {
		existing, findErr := findSupersedingGrantTx(ctx, tx, current, input.Identity, scopeDigest, expiresAt)
		if findErr != nil {
			return Grant{}, findErr
		}
		if err := tx.Commit(); err != nil {
			return Grant{}, err
		}
		return existing, nil
	}
	if current.Status != StatusActive || !current.ExpiresAt.After(now) {
		return Grant{}, ErrInactive
	}
	scopeChanged, err := isScopeSubset(nextScope, current.Scope)
	if err != nil {
		return Grant{}, err
	}
	if !expiresAt.After(now) || expiresAt.After(current.ExpiresAt) {
		return Grant{}, errors.New("narrowed grant expiry must be after now and no later than the current expiry")
	}
	if !scopeChanged && !expiresAt.Before(current.ExpiresAt) {
		return Grant{}, errors.New("authorization narrow request must reduce scope or expiry")
	}
	reason := firstReason(input.Reason, "authorization narrowed")
	if len(reason) > 512 {
		return Grant{}, errors.New("authorization reason exceeds 512 bytes")
	}
	result, err := tx.ExecContext(ctx, `UPDATE authorization_grants
		SET status = 'superseded', updated_at = ?, revoked_at = ?, revocation_reason = ?
		WHERE id = ? AND status = 'active'`, now.UnixMilli(), now.UnixMilli(), reason, current.ID)
	if err != nil {
		return Grant{}, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return Grant{}, ErrInactive
	}
	next := Grant{
		ID:                  "grant_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RemoteSessionID:     current.RemoteSessionID,
		Workspace:           current.Workspace,
		PrincipalID:         current.PrincipalID,
		ContextID:           current.ContextID,
		WorkPackageID:       current.WorkPackageID,
		Goal:                current.Goal,
		Scope:               nextScope,
		ScopeDigest:         scopeDigest,
		Status:              StatusActive,
		SourceRequestID:     firstReason(input.SourceRequestID, current.SourceRequestID),
		SourceCommandDigest: firstReason(input.SourceCommandDigest, current.SourceCommandDigest),
		SupersedesID:        current.ID,
		CreatedAt:           now,
		ExpiresAt:           expiresAt,
		UpdatedAt:           now,
	}
	next.GrantDigest = ComputeGrantDigest(next)
	if err := insertGrantTx(ctx, tx, next); err != nil {
		return Grant{}, err
	}
	if err := tx.Commit(); err != nil {
		return Grant{}, err
	}
	return next, nil
}

func (s *Store) expireActive(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE authorization_grants SET status = 'expired', updated_at = ?
		WHERE status = 'active' AND expires_at <= ?`, now.UnixMilli(), now.UnixMilli())
	return err
}

func expireActiveTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE authorization_grants SET status = 'expired', updated_at = ?
		WHERE status = 'active' AND expires_at <= ?`, now.UnixMilli(), now.UnixMilli())
	return err
}

func findActiveScopeTx(ctx context.Context, tx *sql.Tx, input CreateInput, request Request, scopeDigest string, now time.Time) (Grant, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM authorization_grants
		WHERE remote_session_id = ? AND workspace_name = ? AND principal_id = ?
		AND authorization_context_id = ? AND work_package_id = ? AND goal = ?
		AND scope_digest = ? AND status = 'active' AND expires_at > ?
		ORDER BY created_at DESC LIMIT 1`,
		strings.TrimSpace(input.RemoteSessionID), strings.TrimSpace(input.Workspace), strings.TrimSpace(input.PrincipalID),
		request.ContextID, request.WorkPackageID, request.Goal, scopeDigest, now.UnixMilli())
	grant, err := scanGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	return grant, err
}

func findSupersedingGrantTx(ctx context.Context, tx *sql.Tx, current Grant, identity BoundIdentity, scopeDigest string, expiresAt time.Time) (Grant, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM authorization_grants
		WHERE supersedes_grant_id = ? AND remote_session_id = ? AND workspace_name = ?
		AND principal_id = ? AND authorization_context_id = ? AND scope_digest = ?
		AND expires_at = ? AND status = 'active'
		ORDER BY created_at DESC LIMIT 1`,
		current.ID, identity.RemoteSessionID, identity.Workspace, identity.PrincipalID,
		identity.ContextID, scopeDigest, expiresAt.UnixMilli())
	grant, err := scanGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrInactive
	}
	return grant, err
}

func insertGrantTx(ctx context.Context, tx *sql.Tx, grant Grant) error {
	scopeJSON, err := json.Marshal(grant.Scope)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO authorization_grants
		(id, remote_session_id, workspace_name, principal_id, authorization_context_id,
		 work_package_id, goal, scope_json, scope_digest, grant_digest, status,
		 source_request_id, source_command_digest, supersedes_grant_id,
		 created_at, expires_at, updated_at, revoked_at, revocation_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		grant.ID, grant.RemoteSessionID, grant.Workspace, grant.PrincipalID, grant.ContextID,
		grant.WorkPackageID, grant.Goal, string(scopeJSON), grant.ScopeDigest, grant.GrantDigest, grant.Status,
		grant.SourceRequestID, grant.SourceCommandDigest, nullString(grant.SupersedesID),
		grant.CreatedAt.UnixMilli(), grant.ExpiresAt.UnixMilli(), grant.UpdatedAt.UnixMilli(), nullableTime(grant.RevokedAt), grant.RevocationReason)
	return err
}

func (s *Store) get(ctx context.Context, id string) (Grant, error) {
	grant, err := scanGrant(s.db.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM authorization_grants WHERE id = ?`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	return grant, err
}

func getGrantTx(ctx context.Context, tx *sql.Tx, id string) (Grant, error) {
	grant, err := scanGrant(tx.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM authorization_grants WHERE id = ?`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	return grant, err
}

const grantColumns = `id, remote_session_id, workspace_name, principal_id, authorization_context_id,
	work_package_id, goal, scope_json, scope_digest, grant_digest, status,
	source_request_id, source_command_digest, supersedes_grant_id,
	created_at, expires_at, updated_at, revoked_at, revocation_reason`

type scanner interface{ Scan(dest ...any) error }

func scanGrant(row scanner) (Grant, error) {
	var grant Grant
	var scopeJSON string
	var supersedes sql.NullString
	var createdAt, expiresAt, updatedAt int64
	var revokedAt sql.NullInt64
	if err := row.Scan(
		&grant.ID, &grant.RemoteSessionID, &grant.Workspace, &grant.PrincipalID, &grant.ContextID,
		&grant.WorkPackageID, &grant.Goal, &scopeJSON, &grant.ScopeDigest, &grant.GrantDigest, &grant.Status,
		&grant.SourceRequestID, &grant.SourceCommandDigest, &supersedes,
		&createdAt, &expiresAt, &updatedAt, &revokedAt, &grant.RevocationReason,
	); err != nil {
		return Grant{}, err
	}
	if err := json.Unmarshal([]byte(scopeJSON), &grant.Scope); err != nil {
		return Grant{}, fmt.Errorf("decode authorization scope: %w", err)
	}
	grant.CreatedAt = time.UnixMilli(createdAt).UTC()
	grant.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	grant.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if supersedes.Valid {
		grant.SupersedesID = supersedes.String
	}
	if revokedAt.Valid {
		value := time.UnixMilli(revokedAt.Int64).UTC()
		grant.RevokedAt = &value
	}
	return grant, nil
}

func sameIdentity(grant Grant, identity BoundIdentity) bool {
	return grant.RemoteSessionID == strings.TrimSpace(identity.RemoteSessionID) &&
		grant.Workspace == strings.TrimSpace(identity.Workspace) &&
		grant.PrincipalID == strings.TrimSpace(identity.PrincipalID) &&
		grant.ContextID == strings.TrimSpace(identity.ContextID)
}

func normalizedNow(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func firstReason(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixMilli()
}

func nullString(value string) any {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return nil
}
