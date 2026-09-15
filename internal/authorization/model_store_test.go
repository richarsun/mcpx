package authorization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestRequestDigestStableAndScopeMatch(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	requestA := Request{
		ContextID:     "conversation:861",
		WorkPackageID: "issue-861",
		Goal:          "Implement bounded conversation authorization",
		TTL:           2 * time.Hour,
		Scope: Scope{
			PurposePatterns: []string{"issue 861*"},
			ActionClasses:   []string{"git_local_write", "git_read"},
			Repositories:    []string{"github:Richarsun/MCPX", "workspace:repo"},
			Targets:         []string{"branch:feat/issue-861", "remote:origin:*"},
			WritePaths:      []string{"repo/docs/**", "repo/internal/**"},
			RiskCeiling:     RiskOrdinary,
		},
	}
	requestB := requestA
	requestB.Scope.ActionClasses = []string{"git_read", "git_local_write", "git_read"}
	requestB.Scope.Repositories = []string{"workspace:repo", "github:richarsun/mcpx"}
	requestB.Scope.WritePaths = []string{"repo/internal/**", "repo/docs/**"}

	digestA, err := RequestDigest(requestA)
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := RequestDigest(requestB)
	if err != nil {
		t.Fatal(err)
	}
	if digestA != digestB {
		t.Fatalf("normalized request digests differ: %s != %s", digestA, digestB)
	}

	normalized, err := NormalizeRequest(requestA)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{
		Status:    StatusActive,
		Scope:     normalized.Scope,
		ExpiresAt: now.Add(time.Hour),
	}
	match := Match(grant, "Issue 861 implementation", Action{
		Eligible:     true,
		Risk:         RiskOrdinary,
		Classes:      []string{"git_read", "git_local_write"},
		Repositories: []string{"workspace:repo", "github:richarsun/mcpx"},
		Targets:      []string{"branch:feat/issue-861", "remote:origin:main"},
		WritePaths:   []string{"repo/internal/server/runtime.go", "repo/docs/spec.md"},
	}, now)
	if !match.Matched {
		t.Fatalf("expected bounded action to match: %+v", match)
	}

	mismatch := Match(grant, "Issue 861 implementation", Action{
		Eligible:     true,
		Risk:         RiskOrdinary,
		Classes:      []string{"git_local_write"},
		Repositories: []string{"workspace:other"},
		Targets:      []string{"branch:feat/issue-861"},
		WritePaths:   []string{"repo/secrets/token.txt"},
	}, now)
	if mismatch.Matched {
		t.Fatal("repository and write-domain expansion must not match")
	}
	assertContains(t, mismatch.Reasons, "repository_out_of_scope:workspace:other")
	assertContains(t, mismatch.Reasons, "write_path_out_of_scope:repo/secrets/token.txt")

	highRisk := Match(grant, "Issue 861 implementation", Action{
		Eligible: false,
		Risk:     "high",
		Reasons:  []string{"force_or_delete_git_push"},
	}, now)
	if highRisk.Matched {
		t.Fatal("high-risk action must never match an ordinary grant")
	}
	assertContains(t, highRisk.Reasons, "risk_exceeds_ordinary:high")
	assertContains(t, highRisk.Reasons, "command:force_or_delete_git_push")
}

func TestGrantDigestIgnoresTransportRequestID(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 15, 0, 0, time.UTC)
	grant := Grant{
		ID:                  "grant-861",
		RemoteSessionID:     "session-861",
		Workspace:           "workspace-a",
		PrincipalID:         "principal-a",
		ContextID:           "conversation:861",
		WorkPackageID:       "issue-861",
		Goal:                "Implement bounded conversation authorization",
		ScopeDigest:         "sha256:scope",
		SourceRequestID:     "transport-request-a",
		SourceCommandDigest: "sha256:semantic-confirmation",
		CreatedAt:           now,
		ExpiresAt:           now.Add(time.Hour),
	}

	stable := ComputeGrantDigest(grant)
	grant.SourceRequestID = "transport-request-b"
	if got := ComputeGrantDigest(grant); got != stable {
		t.Fatalf("transport request ID changed stable grant digest: %s != %s", got, stable)
	}

	grant.SourceCommandDigest = "sha256:different-semantic-confirmation"
	if got := ComputeGrantDigest(grant); got == stable {
		t.Fatalf("semantic confirmation change did not change grant digest: %s", got)
	}
}

func TestScopeCanOnlyBeNarrowed(t *testing.T) {
	current := Scope{
		PurposePatterns: []string{"*"},
		ActionClasses:   []string{"git_read", "git_local_write", "git_remote_write"},
		Repositories:    []string{"workspace:repo", "github:richarsun/mcpx"},
		Targets:         []string{"branch:feat/*"},
		WritePaths:      []string{"repo/**"},
		RiskCeiling:     RiskOrdinary,
	}
	narrowed := Scope{
		PurposePatterns: []string{"issue 861 implementation"},
		ActionClasses:   []string{"git_read", "git_local_write"},
		Repositories:    []string{"workspace:repo"},
		Targets:         []string{"branch:feat/issue-861"},
		WritePaths:      []string{"repo/internal/**"},
		RiskCeiling:     RiskOrdinary,
	}
	if ok, err := IsStrictSubset(narrowed, current); err != nil || !ok {
		t.Fatalf("expected strict subset, ok=%v err=%v", ok, err)
	}

	expanded := narrowed
	expanded.Repositories = []string{"workspace:repo", "workspace:other"}
	if _, err := IsStrictSubset(expanded, current); !errors.Is(err, ErrScopeExpansion) {
		t.Fatalf("expected repository expansion rejection, got %v", err)
	}

	slashUnsafeCurrent := current
	slashUnsafeCurrent.Targets = []string{"*"}
	if _, err := IsStrictSubset(narrowed, slashUnsafeCurrent); !errors.Is(err, ErrScopeExpansion) {
		t.Fatalf("path.Match catch-all must not cross slash during narrow: %v", err)
	}

	same := current
	if _, err := IsStrictSubset(same, current); err == nil {
		t.Fatal("unchanged scope is not a narrow operation")
	}
}

func TestStoreConcurrentCreateOrReuseReturnsOneGrant(t *testing.T) {
	db := newAuthorizationTestDB(t)
	store := NewStore(db)
	ctx := context.Background()
	now := time.Date(2026, 9, 15, 0, 30, 0, 0, time.UTC)
	base := CreateInput{
		RemoteSessionID:     "session-861-concurrent",
		Workspace:           "workspace-a",
		PrincipalID:         "principal-a",
		SourceCommandDigest: "sha256:semantic-confirmation",
		Request:             testAuthorizationRequest(),
		Now:                 now,
	}

	const workers = 8
	type result struct {
		grant  Grant
		reused bool
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			<-start
			input := base
			input.SourceRequestID = fmt.Sprintf("request-%d", index)
			grant, reused, err := store.CreateOrReuse(ctx, input)
			results <- result{grant: grant, reused: reused, err: err}
		}(index)
	}
	close(start)

	grantIDs := map[string]bool{}
	created := 0
	for index := 0; index < workers; index++ {
		item := <-results
		if item.err != nil {
			t.Fatalf("concurrent authorization retry failed: %v", item.err)
		}
		grantIDs[item.grant.ID] = true
		if !item.reused {
			created++
		}
	}
	if len(grantIDs) != 1 || created != 1 {
		t.Fatalf("concurrent retries produced duplicate grants: ids=%v created=%d", grantIDs, created)
	}
}

func TestStoreLifecycleContextIsolationAndRecovery(t *testing.T) {
	db := newAuthorizationTestDB(t)
	store := NewStore(db)
	ctx := context.Background()
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	request := testAuthorizationRequest()
	input := CreateInput{
		RemoteSessionID:     "session-861",
		Workspace:           "workspace-a",
		PrincipalID:         "principal-a",
		SourceRequestID:     "request-1",
		SourceCommandDigest: "sha256:command-1",
		Request:             request,
		Now:                 now,
	}

	created, reused, err := store.CreateOrReuse(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if reused || created.ID == "" || created.ScopeDigest == "" || created.GrantDigest == "" {
		t.Fatalf("unexpected created grant: reused=%v grant=%+v", reused, created)
	}

	recoveredStore := NewStore(db)
	recovered, reused, err := recoveredStore.CreateOrReuse(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reused || recovered.ID != created.ID {
		t.Fatalf("retry/recovery created duplicate grant: first=%s second=%s reused=%v", created.ID, recovered.ID, reused)
	}

	changedConfirmation := input
	changedConfirmation.SourceRequestID = "request-shorter-ttl"
	changedConfirmation.SourceCommandDigest = "sha256:command-shorter-ttl"
	changedConfirmation.Request.TTL = 5 * time.Minute
	changedConfirmation.Now = now.Add(time.Minute)
	if _, _, err := recoveredStore.CreateOrReuse(ctx, changedConfirmation); !errors.Is(err, ErrActiveScopeConflict) {
		t.Fatalf("different confirmation/TTL silently reused active grant: %v", err)
	}
	unchanged, err := recoveredStore.GetBound(ctx, BoundIdentity{
		RemoteSessionID: input.RemoteSessionID,
		Workspace:       input.Workspace,
		PrincipalID:     input.PrincipalID,
		ContextID:       request.ContextID,
	}, created.ID, now.Add(time.Minute))
	if err != nil || !unchanged.ExpiresAt.Equal(created.ExpiresAt) || unchanged.Status != StatusActive {
		t.Fatalf("conflicting reauthorization changed existing grant: %+v err=%v", unchanged, err)
	}

	identity := BoundIdentity{
		RemoteSessionID: input.RemoteSessionID,
		Workspace:       input.Workspace,
		PrincipalID:     input.PrincipalID,
		ContextID:       request.ContextID,
	}
	bound, err := recoveredStore.GetBound(ctx, identity, created.ID, now.Add(time.Minute))
	if err != nil || bound.ID != created.ID {
		t.Fatalf("bound grant lookup failed: grant=%+v err=%v", bound, err)
	}
	newConversation := identity
	newConversation.ContextID = "conversation:new"
	if _, err := recoveredStore.GetBound(ctx, newConversation, created.ID, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new conversation inherited old grant: %v", err)
	}
	newWorkspace := identity
	newWorkspace.Workspace = "workspace-b"
	if _, err := recoveredStore.GetBound(ctx, newWorkspace, created.ID, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new workspace inherited old grant: %v", err)
	}

	revoked, err := recoveredStore.Revoke(ctx, identity, created.ID, "user reduced the work package", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != StatusRevoked || revoked.RevokedAt == nil {
		t.Fatalf("grant not revoked: %+v", revoked)
	}
	view := PublicView(revoked)
	if view["revoked_at"] != revoked.RevokedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("public audit view omitted revoked_at: %+v", view)
	}
	postRevoke := Match(revoked, "issue 861 implementation", Action{
		Eligible:     true,
		Risk:         RiskOrdinary,
		Classes:      []string{"git_read"},
		Repositories: []string{"workspace:repo"},
	}, now.Add(3*time.Minute))
	if postRevoke.Matched {
		t.Fatal("revoked grant still matched next action")
	}
	assertContains(t, postRevoke.Reasons, "grant_status:revoked")

	input.SourceRequestID = "request-2"
	input.SourceCommandDigest = "sha256:command-2"
	input.Now = now.Add(4 * time.Minute)
	replacement, reused, err := recoveredStore.CreateOrReuse(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if reused || replacement.ID == created.ID {
		t.Fatalf("revoked grant must not be reused: %+v", replacement)
	}
}

func TestStoreNarrowAndExpiry(t *testing.T) {
	db := newAuthorizationTestDB(t)
	store := NewStore(db)
	ctx := context.Background()
	now := time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)
	request := testAuthorizationRequest()
	request.Scope.PurposePatterns = []string{"*"}
	request.Scope.ActionClasses = []string{"git_read", "git_local_write", "git_remote_write"}
	request.Scope.Repositories = []string{"workspace:repo", "github:richarsun/mcpx"}
	request.Scope.Targets = []string{"branch:feat/*", "remote:origin:feat/*"}
	request.Scope.WritePaths = []string{"repo/**"}
	request.TTL = time.Hour
	input := CreateInput{
		RemoteSessionID:     "session-861",
		Workspace:           "workspace-a",
		PrincipalID:         "principal-a",
		SourceRequestID:     "request-narrow",
		SourceCommandDigest: "sha256:narrow-source",
		Request:             request,
		Now:                 now,
	}
	original, _, err := store.CreateOrReuse(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	identity := BoundIdentity{
		RemoteSessionID: input.RemoteSessionID,
		Workspace:       input.Workspace,
		PrincipalID:     input.PrincipalID,
		ContextID:       request.ContextID,
	}

	expanded := original.Scope
	expanded.Repositories = append(expanded.Repositories, "workspace:other")
	if _, err := store.Narrow(ctx, NarrowInput{
		Identity: identity,
		GrantID:  original.ID,
		Scope:    expanded,
		Now:      now.Add(time.Minute),
	}); !errors.Is(err, ErrScopeExpansion) {
		t.Fatalf("scope expansion was not rejected: %v", err)
	}
	stillActive, err := store.GetBound(ctx, identity, original.ID, now.Add(time.Minute))
	if err != nil || stillActive.Status != StatusActive {
		t.Fatalf("failed narrow must leave original active: %+v err=%v", stillActive, err)
	}

	narrowScope := Scope{
		PurposePatterns: []string{"issue 861 implementation"},
		ActionClasses:   []string{"git_read", "git_local_write"},
		Repositories:    []string{"workspace:repo"},
		Targets:         []string{"branch:feat/issue-861"},
		WritePaths:      []string{"repo/internal/**"},
		RiskCeiling:     RiskOrdinary,
	}
	narrowed, err := store.Narrow(ctx, NarrowInput{
		Identity:        identity,
		GrantID:         original.ID,
		Scope:           narrowScope,
		ExpiresAt:       now.Add(30 * time.Minute),
		SourceRequestID: "request-narrow-2",
		Reason:          "remove remote write and docs",
		Now:             now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if narrowed.ID == original.ID || narrowed.SupersedesID != original.ID || narrowed.Status != StatusActive {
		t.Fatalf("unexpected narrowed grant: %+v", narrowed)
	}

	// A client may lose the first response after the transaction commits. An
	// exact retry must recover the already-created replacement instead of
	// producing a duplicate grant or treating the superseded source as an
	// unrelated inactive grant.
	recoveredNarrow, err := store.Narrow(ctx, NarrowInput{
		Identity:        identity,
		GrantID:         original.ID,
		Scope:           narrowScope,
		ExpiresAt:       now.Add(30 * time.Minute),
		SourceRequestID: "request-narrow-2",
		Reason:          "remove remote write and docs",
		Now:             now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatalf("narrow retry did not recover committed replacement: %v", err)
	}
	if recoveredNarrow.ID != narrowed.ID || recoveredNarrow.GrantDigest != narrowed.GrantDigest {
		t.Fatalf("narrow retry created or returned a different grant: first=%+v recovered=%+v", narrowed, recoveredNarrow)
	}

	old, err := store.GetBound(ctx, identity, original.ID, now.Add(3*time.Minute))
	if err != nil || old.Status != StatusSuperseded {
		t.Fatalf("old grant not superseded: %+v err=%v", old, err)
	}

	active, err := store.List(ctx, identity, false, now.Add(3*time.Minute))
	if err != nil || len(active) != 1 || active[0].ID != narrowed.ID {
		t.Fatalf("active grant list mismatch: %+v err=%v", active, err)
	}
	active, err = store.List(ctx, identity, false, now.Add(31*time.Minute))
	if err != nil || len(active) != 0 {
		t.Fatalf("expired grant remained active: %+v err=%v", active, err)
	}
	all, err := store.List(ctx, identity, true, now.Add(31*time.Minute))
	if err != nil || len(all) != 2 {
		t.Fatalf("grant history mismatch: %+v err=%v", all, err)
	}
	statuses := []string{all[0].Status, all[1].Status}
	if !reflect.DeepEqual(statuses, []string{StatusExpired, StatusSuperseded}) {
		t.Fatalf("unexpected recovered statuses: %+v", statuses)
	}
}

func TestStoreNarrowCanShortenExpiryOnly(t *testing.T) {
	db := newAuthorizationTestDB(t)
	store := NewStore(db)
	ctx := context.Background()
	now := time.Date(2026, 9, 15, 4, 0, 0, 0, time.UTC)
	request := testAuthorizationRequest()
	request.TTL = time.Hour
	input := CreateInput{
		RemoteSessionID:     "session-861-expiry",
		Workspace:           "workspace-a",
		PrincipalID:         "principal-a",
		SourceRequestID:     "request-expiry",
		SourceCommandDigest: "sha256:expiry-source",
		Request:             request,
		Now:                 now,
	}
	original, _, err := store.CreateOrReuse(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	identity := BoundIdentity{
		RemoteSessionID: input.RemoteSessionID,
		Workspace:       input.Workspace,
		PrincipalID:     input.PrincipalID,
		ContextID:       request.ContextID,
	}
	expiresAt := now.Add(30 * time.Minute)
	narrowInput := NarrowInput{
		Identity:            identity,
		GrantID:             original.ID,
		Scope:               original.Scope,
		ExpiresAt:           expiresAt,
		SourceRequestID:     "request-expiry-narrow",
		SourceCommandDigest: "sha256:expiry-narrow",
		Reason:              "shorten authorization lifetime",
		Now:                 now.Add(time.Minute),
	}
	narrowed, err := store.Narrow(ctx, narrowInput)
	if err != nil {
		t.Fatal(err)
	}
	if narrowed.ID == original.ID || narrowed.SupersedesID != original.ID {
		t.Fatalf("expiry-only narrow did not replace the original grant: %+v", narrowed)
	}
	if narrowed.ScopeDigest != original.ScopeDigest || !narrowed.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expiry-only narrow changed scope or expiry incorrectly: original=%+v narrowed=%+v", original, narrowed)
	}

	narrowInput.Now = now.Add(2 * time.Minute)
	recovered, err := store.Narrow(ctx, narrowInput)
	if err != nil {
		t.Fatalf("expiry-only narrow retry did not recover replacement: %v", err)
	}
	if recovered.ID != narrowed.ID || recovered.GrantDigest != narrowed.GrantDigest {
		t.Fatalf("expiry-only narrow retry returned a different grant: first=%+v recovered=%+v", narrowed, recovered)
	}
}

func testAuthorizationRequest() Request {
	return Request{
		ContextID:     "conversation:861",
		WorkPackageID: "issue-861",
		Goal:          "Implement issue 861",
		TTL:           time.Hour,
		Scope: Scope{
			PurposePatterns: []string{"issue 861*"},
			ActionClasses:   []string{"git_read", "git_local_write"},
			Repositories:    []string{"workspace:repo"},
			Targets:         []string{"branch:feat/issue-861"},
			WritePaths:      []string{"repo/internal/**"},
			RiskCeiling:     RiskOrdinary,
		},
	}
}

func newAuthorizationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`CREATE TABLE authorization_grants (
		id TEXT PRIMARY KEY,
		remote_session_id TEXT NOT NULL,
		workspace_name TEXT NOT NULL,
		principal_id TEXT NOT NULL,
		authorization_context_id TEXT NOT NULL,
		work_package_id TEXT NOT NULL,
		goal TEXT NOT NULL,
		scope_json TEXT NOT NULL,
		scope_digest TEXT NOT NULL,
		grant_digest TEXT NOT NULL,
		status TEXT NOT NULL,
		source_request_id TEXT NOT NULL,
		source_command_digest TEXT NOT NULL,
		supersedes_grant_id TEXT,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		revoked_at INTEGER,
		revocation_reason TEXT NOT NULL DEFAULT ''
	);
	CREATE UNIQUE INDEX uq_authorization_grants_active_scope
		ON authorization_grants(remote_session_id, workspace_name, principal_id,
			authorization_context_id, work_package_id, goal, scope_digest)
		WHERE status = 'active';`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func assertContains(t *testing.T, values []string, expected string) {
	t.Helper()
	for _, value := range values {
		if value == expected {
			return
		}
	}
	t.Fatalf("%q not found in %+v", expected, values)
}
