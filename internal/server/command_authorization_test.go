package server

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/audit"
	"mcpx/internal/authorization"
	"mcpx/internal/config"
)

const (
	issue861ContextID = "conversation:issue-861-runtime"
	issue861Purpose   = "issue 861 implementation"
)

func TestConversationAuthorizationAuditDistinguishesRecordRecoveryFromConfirmationBypass(t *testing.T) {
	state := commandAuthorizationState{
		Decision: "grant_reused_after_confirmation",
		Grant: &authorization.Grant{
			ID:          "grant-recovered",
			GrantDigest: "sha256:recovered",
		},
	}
	data := state.data()
	if data["grant_reused"] != true {
		t.Fatalf("recovered grant record was not identified as reused: %+v", data)
	}
	if data["grant_used_for_confirmation_bypass"] != false {
		t.Fatalf("exact confirmed retry was incorrectly audited as confirmation bypass: %+v", data)
	}

	state.Decision = "grant_reused"
	data = state.data()
	if data["grant_reused"] != true || data["grant_used_for_confirmation_bypass"] != true {
		t.Fatalf("ordinary grant reuse did not record confirmation bypass: %+v", data)
	}
}

func TestConversationAuthorizationGrantReusesBoundedGitWorkPackage(t *testing.T) {
	rt, remoteID, workspace, auditPath := newIssue861Runtime(t)
	runIssue861Git(t, workspace, "-C", "repo", "push", "origin", "feat/issue-861")
	grantID := createIssue861Grant(t, rt, remoteID)
	reusedCommands := 0
	run := func(command string) {
		response := runIssue861AuthorizedCommand(t, rt, remoteID, grantID, issue861ContextID, issue861Purpose, command)
		assertIssue861GrantReuse(t, response, grantID)
		reusedCommands++
	}

	run("git -C repo status --short")
	run("git -C repo fetch --no-tags --refmap= origin feat/issue-861")
	run("git -C repo switch -c feat/issue-861-e2e")

	if err := os.WriteFile(filepath.Join(workspace, "repo", "docs", "allowed.md"), []byte("base\nnext\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("git -C repo diff --no-ext-diff --no-textconv -- docs/allowed.md")
	run("git -C repo add -- docs/allowed.md")
	run("git -C repo commit -m issue-861-runtime")
	run("git -C repo push origin feat/issue-861-e2e")
	run("git -C repo switch -c feat/issue-861-holder")
	run("git -C repo branch -d feat/issue-861-e2e")

	events := readIssue861Audit(t, auditPath)
	created := false
	reusedPreflights := 0
	for _, event := range events {
		status, _ := event["status"].(string)
		if status == "grant_created" {
			created = true
		}
		if status != "preflight_approved" {
			continue
		}
		detail, _ := event["detail"].(map[string]any)
		authorization, _ := detail["authorization"].(map[string]any)
		if authorization["decision"] != "grant_reused" {
			continue
		}
		reusedPreflights++
		if authorization["grant_reused"] != true {
			t.Fatalf("reused preflight did not identify grant reuse: %+v", authorization)
		}
		source, _ := authorization["grant_source"].(map[string]any)
		if source["grant_id"] != grantID || strings.TrimSpace(stringValue(source["grant_digest"])) == "" || strings.TrimSpace(stringValue(source["source_command_digest"])) == "" {
			t.Fatalf("audit omitted stable grant provenance: %+v", authorization)
		}
		if !jsonStringSliceContains(authorization["match_basis"], "principal_context_remote_session_workspace_binding_verified") {
			t.Fatalf("audit omitted positive scope-match basis: %+v", authorization)
		}
	}
	if !created || reusedPreflights < reusedCommands {
		t.Fatalf("authorization audit incomplete: grant_created=%v reused_preflights=%d expected=%d events=%+v", created, reusedPreflights, reusedCommands, events)
	}
}

func TestConversationAuthorizationRecoveryArgumentsRoundTripWithoutOptionalArrays(t *testing.T) {
	rt, remoteID, _, _ := newIssue861Runtime(t)
	waiting := callEnvelope(t, rt.toolExecute, context.Background(), map[string]any{
		"action":                   "run",
		"remote_session_id":        remoteID,
		"purpose":                  issue861Purpose,
		"command":                  "git -C repo status --short",
		"scope":                    "workspace",
		"authorization_context_id": "conversation:issue-861-read-only",
		"authorization_request": map[string]any{
			"work_package_id":    "issue-861-read-only",
			"work_package_goal":  "Read one bounded repository",
			"purpose_patterns":   []string{"issue 861*"},
			"action_classes":     []string{"git_read"},
			"repositories":       []string{"workspace:repo"},
			"targets":            []string{"branch:feat/issue-861"},
			"risk_ceiling":       "ordinary",
			"expires_in_seconds": 3600,
		},
	})
	if waiting["status"] != "waiting_confirmation" || errorCode(waiting) != "user_confirmation_required" {
		t.Fatalf("read-only authorization did not request one confirmation: %+v", waiting)
	}
	errorBody, ok := waiting["error"].(map[string]any)
	if !ok {
		t.Fatalf("confirmation error body missing: %+v", waiting)
	}
	details, ok := errorBody["details"].(map[string]any)
	if !ok {
		t.Fatalf("confirmation details missing: %+v", errorBody)
	}
	nextAction, ok := details["next_action"].(map[string]any)
	if !ok {
		t.Fatalf("confirmation next_action missing: %+v", details)
	}
	retryArguments, ok := nextAction["arguments"].(map[string]any)
	if !ok {
		t.Fatalf("confirmation retry arguments missing: %+v", nextAction)
	}
	retryAuthorization, ok := retryArguments["authorization_request"].(map[string]any)
	if !ok {
		t.Fatalf("confirmation retry authorization missing: %+v", retryArguments)
	}
	if !jsonStringSliceContains(retryAuthorization["targets"], "branch:feat/issue-861") {
		t.Fatalf("recovery arguments dropped the read target: %+v", retryAuthorization)
	}
	if value, exists := retryAuthorization["write_paths"]; exists {
		t.Fatalf("empty optional write_paths must be omitted, got %#v", value)
	}
	if retryArguments["user_confirmed"] != true {
		t.Fatalf("recovery arguments did not carry user_confirmed=true: %+v", retryArguments)
	}
	confirmed := callEnvelope(t, rt.toolExecute, context.Background(), cloneMap(retryArguments))
	if !statusOK(confirmed) {
		t.Fatalf("server-provided recovery arguments were not directly reusable: %+v", confirmed)
	}
	authorization, _ := responseData(t, confirmed)["authorization"].(map[string]any)
	if authorization["decision"] != "grant_created" || authorization["matched"] != true {
		t.Fatalf("recovery arguments did not create the read-only grant: %+v", authorization)
	}
}

func TestConversationAuthorizationCompoundCommandFallsBackToConfirmation(t *testing.T) {
	rt, remoteID, _, _ := newIssue861Runtime(t)
	grantID := createIssue861Grant(t, rt, remoteID)
	response := runIssue861AuthorizedCommand(
		t, rt, remoteID, grantID, issue861ContextID, issue861Purpose,
		"git -C repo status --short; git -C repo status --short",
	)
	assertIssue861NeedsConfirmation(t, response, "command:compound_commands_not_grant_eligible")
}

func TestConversationAuthorizationPinsExecutableAgainstWorkspaceShadow(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows cmd executable-shadow regression")
	}
	rt, remoteID, workspace, _ := newIssue861Runtime(t)
	shadowHit := filepath.Join(workspace, "shadow-hit.txt")
	shadow := "@echo off\r\n> \"%~dp0shadow-hit.txt\" echo shadow\r\nexit /b 0\r\n"
	if err := os.WriteFile(filepath.Join(workspace, "git.cmd"), []byte(shadow), 0o600); err != nil {
		t.Fatal(err)
	}

	grantID := createIssue861Grant(t, rt, remoteID)
	if _, err := os.Stat(shadowHit); !os.IsNotExist(err) {
		t.Fatalf("initial grant execution used Workspace git.cmd: %v", err)
	}
	response := runIssue861AuthorizedCommand(t, rt, remoteID, grantID, issue861ContextID, issue861Purpose, "git -C repo status --short")
	assertIssue861GrantReuse(t, response, grantID)
	if _, err := os.Stat(shadowHit); !os.IsNotExist(err) {
		t.Fatalf("grant reuse used Workspace git.cmd instead of the pinned executable: %v", err)
	}
}

func TestConversationAuthorizationLifecycleRecoveryNarrowAndRevoke(t *testing.T) {
	rt, remoteID, workspace, auditPath := newIssue861Runtime(t)
	grantID := createIssue861Grant(t, rt, remoteID)

	recovered := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{
		"action":                   "open",
		"remote_session_id":        remoteID,
		"authorization_context_id": issue861ContextID,
	})
	if !statusOK(recovered) {
		t.Fatalf("session recovery failed: %+v", recovered)
	}
	recoveredData := responseData(t, recovered)
	if recoveredData["authorization_context_id"] != issue861ContextID || !grantListContains(recoveredData["authorization_grants"], grantID) {
		t.Fatalf("session recovery did not return the bound grant: %+v", recoveredData)
	}

	withoutContext := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{
		"action": "open", "remote_session_id": remoteID,
	})
	if !statusOK(withoutContext) {
		t.Fatalf("session resume without context failed: %+v", withoutContext)
	}
	if _, inherited := responseData(t, withoutContext)["authorization_grants"]; inherited {
		t.Fatalf("session resume without explicit conversation context inherited grants: %+v", withoutContext)
	}

	listed := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{
		"action":                   "authorization_list",
		"remote_session_id":        remoteID,
		"authorization_context_id": issue861ContextID,
	})
	if !statusOK(listed) || !grantListContains(responseData(t, listed)["authorization_grants"], grantID) {
		t.Fatalf("authorization_list did not return active grant: %+v", listed)
	}

	narrowRequest := map[string]any{
		"action":                   "authorization_narrow",
		"remote_session_id":        remoteID,
		"purpose":                  "narrow issue 861 authorization to read only",
		"authorization_context_id": issue861ContextID,
		"authorization_grant_id":   grantID,
		"authorization_reason":     "remove Git mutation permission",
		"authorization_scope": map[string]any{
			"purpose_patterns": []string{"issue 861*"},
			"action_classes":   []string{"git_read"},
			"repositories":     []string{"workspace:repo"},
			"targets":          []string{"branch:feat/*"},
			"risk_ceiling":     "ordinary",
		},
	}
	narrowed := callEnvelope(t, rt.toolSession, context.Background(), narrowRequest)
	if !statusOK(narrowed) {
		t.Fatalf("authorization_narrow failed: %+v", narrowed)
	}
	narrowedGrant := responseData(t, narrowed)["authorization_grant"].(map[string]any)
	narrowedID := stringValue(narrowedGrant["grant_id"])
	if narrowedID == "" || narrowedID == grantID || narrowedGrant["supersedes_grant_id"] != grantID || narrowedGrant["status"] != "active" {
		t.Fatalf("unexpected narrowed grant: %+v", narrowedGrant)
	}

	// Simulate a lost response: the exact retry must recover the same replacement.
	narrowedRetry := callEnvelope(t, rt.toolSession, context.Background(), cloneMap(narrowRequest))
	if !statusOK(narrowedRetry) {
		t.Fatalf("authorization_narrow retry failed: %+v", narrowedRetry)
	}
	recoveredGrant := responseData(t, narrowedRetry)["authorization_grant"].(map[string]any)
	if recoveredGrant["grant_id"] != narrowedID || recoveredGrant["grant_digest"] != narrowedGrant["grant_digest"] {
		t.Fatalf("narrow retry returned a different grant: first=%+v retry=%+v", narrowedGrant, recoveredGrant)
	}

	read := runIssue861AuthorizedCommand(t, rt, remoteID, narrowedID, issue861ContextID, issue861Purpose, "git -C repo status --short")
	assertIssue861GrantReuse(t, read, narrowedID)

	if err := os.WriteFile(filepath.Join(workspace, "repo", "docs", "narrowed.md"), []byte("narrowed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutation := runIssue861AuthorizedCommand(t, rt, remoteID, narrowedID, issue861ContextID, issue861Purpose, "git -C repo add -- docs/narrowed.md")
	assertIssue861NeedsConfirmation(t, mutation, "action_class_out_of_scope:git_local_write")

	revokeRequest := map[string]any{
		"action":                   "authorization_revoke",
		"remote_session_id":        remoteID,
		"purpose":                  "revoke issue 861 authorization",
		"authorization_context_id": issue861ContextID,
		"authorization_grant_id":   narrowedID,
		"authorization_reason":     "user ended the work package",
	}
	revoked := callEnvelope(t, rt.toolSession, context.Background(), revokeRequest)
	if !statusOK(revoked) || responseData(t, revoked)["authorization_grant"].(map[string]any)["status"] != "revoked" {
		t.Fatalf("authorization_revoke failed: %+v", revoked)
	}
	revokedRetry := callEnvelope(t, rt.toolSession, context.Background(), cloneMap(revokeRequest))
	if !statusOK(revokedRetry) || responseData(t, revokedRetry)["authorization_grant"].(map[string]any)["grant_id"] != narrowedID {
		t.Fatalf("authorization_revoke was not idempotent: %+v", revokedRetry)
	}

	postRevoke := runIssue861AuthorizedCommand(t, rt, remoteID, narrowedID, issue861ContextID, issue861Purpose, "git -C repo status --short")
	assertIssue861NeedsConfirmation(t, postRevoke, "grant_status:revoked")

	activeAfterRevoke := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{
		"action":                   "authorization_list",
		"remote_session_id":        remoteID,
		"authorization_context_id": issue861ContextID,
	})
	if !statusOK(activeAfterRevoke) || responseData(t, activeAfterRevoke)["count"] != float64(0) {
		t.Fatalf("revoked grant remained active: %+v", activeAfterRevoke)
	}
	history := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{
		"action":                         "authorization_list",
		"remote_session_id":              remoteID,
		"authorization_context_id":       issue861ContextID,
		"authorization_include_inactive": true,
	})
	if !statusOK(history) || responseData(t, history)["count"] != float64(2) {
		t.Fatalf("authorization history did not preserve superseded and revoked grants: %+v", history)
	}

	statuses := map[string]bool{}
	for _, event := range readIssue861Audit(t, auditPath) {
		if status, _ := event["status"].(string); strings.HasPrefix(status, "authorization_") {
			statuses[status] = true
		}
	}
	for _, required := range []string{"authorization_listed", "authorization_narrowed", "authorization_revoked", "authorization_confirmation_required"} {
		if !statuses[required] {
			t.Fatalf("missing lifecycle audit %q in %+v", required, statuses)
		}
	}
}

func TestConversationAuthorizationIdempotentReplaySurvivesGrantRevocation(t *testing.T) {
	rt, remoteID, _, _ := newIssue861Runtime(t)
	grantID := createIssue861Grant(t, rt, remoteID)
	request := map[string]any{
		"action":                   "run",
		"remote_session_id":        remoteID,
		"purpose":                  issue861Purpose,
		"command":                  "git -C repo status --short",
		"scope":                    "workspace",
		"idempotency_key":          "issue-861-recovery-replay",
		"authorization_context_id": issue861ContextID,
		"authorization_grant_id":   grantID,
	}
	completed := callEnvelope(t, rt.toolExecute, context.Background(), cloneMap(request))
	if !statusOK(completed) {
		t.Fatalf("grant-backed idempotent command failed: %+v", completed)
	}

	revoked := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{
		"action":                   "authorization_revoke",
		"remote_session_id":        remoteID,
		"purpose":                  "revoke issue 861 authorization after completed request",
		"authorization_context_id": issue861ContextID,
		"authorization_grant_id":   grantID,
		"authorization_reason":     "exercise durable retry recovery",
	})
	if !statusOK(revoked) {
		t.Fatalf("authorization_revoke failed: %+v", revoked)
	}

	replayed := callEnvelope(t, rt.toolExecute, context.Background(), cloneMap(request))
	if !statusOK(replayed) || responseData(t, replayed)["idempotent_replay"] != true {
		t.Fatalf("completed request was not replayed after grant revocation: %+v", replayed)
	}

	changed := cloneMap(request)
	changed["purpose"] = "unrelated maintenance"
	conflict := callEnvelope(t, rt.toolExecute, context.Background(), changed)
	if statusOK(conflict) || errorCode(conflict) != "idempotency_conflict" {
		t.Fatalf("changed authorization purpose did not conflict with durable replay: %+v", conflict)
	}
}

func TestConversationAuthorizationBoundaryChangesAndDenyTakePriority(t *testing.T) {
	rt, remoteID, workspace, auditPath := newIssue861Runtime(t)
	grantID := createIssue861Grant(t, rt, remoteID)

	if err := os.WriteFile(filepath.Join(workspace, "repo", "other.txt"), []byte("outside authorized write domain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideWrite := runIssue861AuthorizedCommand(t, rt, remoteID, grantID, issue861ContextID, issue861Purpose, "git -C repo add -- other.txt")
	assertIssue861NeedsConfirmation(t, outsideWrite, "write_path_out_of_scope:repo/other.txt")

	changedPurpose := runIssue861AuthorizedCommand(t, rt, remoteID, grantID, issue861ContextID, "unrelated maintenance", "git -C repo status --short")
	assertIssue861NeedsConfirmation(t, changedPurpose, "purpose_out_of_scope")

	newConversation := runIssue861AuthorizedCommand(t, rt, remoteID, grantID, "conversation:new", issue861Purpose, "git -C repo status --short")
	assertIssue861NeedsConfirmation(t, newConversation, "grant_not_found_for_current_principal_context_session_workspace")

	initIssue861Repository(t, workspace, "repo-two", false)
	newRepository := runIssue861AuthorizedCommand(t, rt, remoteID, grantID, issue861ContextID, issue861Purpose, "git -C repo-two status --short")
	assertIssue861NeedsConfirmation(t, newRepository, "repository_out_of_scope:workspace:repo-two")

	otherWorkspace, ok := rt.reg.Get("other")
	if !ok {
		t.Fatal("other workspace not registered")
	}
	initIssue861Repository(t, otherWorkspace.Path, "repo", false)
	otherSession := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{"action": "open", "workspace": "other"})
	if !statusOK(otherSession) {
		t.Fatalf("open other workspace session: %+v", otherSession)
	}
	otherRemoteID := stringValue(otherSession["remote_session_id"])
	newWorkspace := runIssue861AuthorizedCommand(t, rt, otherRemoteID, grantID, issue861ContextID, issue861Purpose, "git -C repo status --short")
	assertIssue861NeedsConfirmation(t, newWorkspace, "grant_not_found_for_current_principal_context_session_workspace")

	forcePush := runIssue861AuthorizedCommand(t, rt, remoteID, grantID, issue861ContextID, issue861Purpose, "git -C repo push --force origin feat/issue-861")
	if statusOK(forcePush) || errorCode(forcePush) != "denied" {
		t.Fatalf("deny did not take priority over grant: %+v", forcePush)
	}
	remotePath := filepath.Join(workspace, "remote.git")
	command := exec.Command("git", "ls-remote", remotePath, "refs/heads/feat/issue-861")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git ls-remote: %v", err)
	}
	if strings.TrimSpace(string(output)) != "" {
		t.Fatalf("force push executed despite deny: %s", output)
	}

	deniedAudit := false
	for _, event := range readIssue861Audit(t, auditPath) {
		if event["status"] != "denied" || !strings.Contains(stringValue(event["command"]), "--force") {
			continue
		}
		detail, _ := event["detail"].(map[string]any)
		authorization, _ := detail["authorization"].(map[string]any)
		if authorization["decision"] == "denied_by_command_policy" {
			deniedAudit = true
		}
	}
	if !deniedAudit {
		t.Fatalf("deny audit did not explain authorization non-reuse")
	}
}

func TestConversationAuthorizationIdempotencyBindsSecurityBoundary(t *testing.T) {
	base := map[string]any{
		"action":                   "run",
		"remote_session_id":        "session-861",
		"command":                  "git -C repo status --short",
		"scope":                    "workspace",
		"purpose":                  "issue 861 implementation",
		"idempotency_key":          "issue-861-key",
		"authorization_context_id": "conversation:861",
		"authorization_grant_id":   "grant-861",
	}
	original := cleanIdempotencyFingerprint("execute", base)

	retry := cloneMap(base)
	retry["user_confirmed"] = true
	retry["request_id"] = "transport-retry"
	if got := cleanIdempotencyFingerprint("execute", retry); got != original {
		t.Fatalf("transport retry metadata changed fingerprint: %s != %s", got, original)
	}

	for name, mutate := range map[string]func(map[string]any){
		"conversation": func(payload map[string]any) { payload["authorization_context_id"] = "conversation:new" },
		"grant":        func(payload map[string]any) { payload["authorization_grant_id"] = "grant-new" },
		"purpose":      func(payload map[string]any) { payload["purpose"] = "unrelated maintenance" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneMap(base)
			mutate(changed)
			if got := cleanIdempotencyFingerprint("execute", changed); got == original {
				t.Fatalf("authorization boundary change reused fingerprint %s", got)
			}
		})
	}

	requestPayload := cloneMap(base)
	delete(requestPayload, "authorization_grant_id")
	requestPayload["authorization_request"] = map[string]any{
		"work_package_id":    "issue-861",
		"work_package_goal":  "Implement bounded authorization",
		"purpose_patterns":   []string{"issue 861*"},
		"action_classes":     []string{"git_read"},
		"repositories":       []string{"workspace:repo"},
		"risk_ceiling":       "ordinary",
		"expires_in_seconds": 3600,
	}
	requestFingerprint := cleanIdempotencyFingerprint("execute", requestPayload)
	changedRequest := cloneMap(requestPayload)
	request := cloneMap(requestPayload["authorization_request"].(map[string]any))
	request["expires_in_seconds"] = 300
	changedRequest["authorization_request"] = request
	if got := cleanIdempotencyFingerprint("execute", changedRequest); got == requestFingerprint {
		t.Fatalf("authorization request TTL change reused fingerprint %s", got)
	}
}

func TestConversationAuthorizationSchemaDoesNotExtendMoveOutProtocol(t *testing.T) {
	rt := newWorkspaceRuntime(t, "demo")
	protocol := mcp.NewServer(&mcp.Implementation{Name: "mcpx-issue-861-test", Version: "0.1.0"}, nil)
	rt.registerTools(protocol)
	tools := rt.listedToolMap()

	moveOutJSON, err := json.Marshal(tools["move_out"].InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"authorization_context_id", "authorization_grant_id", "authorization_request", "authorization_narrow", "authorization_revoke"} {
		if strings.Contains(string(moveOutJSON), forbidden) {
			t.Fatalf("move_out protocol was silently extended by conversation grants: %s", moveOutJSON)
		}
	}

	executeJSON, err := json.Marshal(tools["execute"].InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"authorization_context_id", "authorization_grant_id", "authorization_request", "work_package_goal"} {
		if !strings.Contains(string(executeJSON), required) {
			t.Fatalf("execute schema missing %q: %s", required, executeJSON)
		}
	}
	sessionJSON, err := json.Marshal(tools["session"].InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"authorization_list", "authorization_narrow", "authorization_revoke", "authorization_scope"} {
		if !strings.Contains(string(sessionJSON), required) {
			t.Fatalf("session schema missing %q: %s", required, sessionJSON)
		}
	}
}

func newIssue861Runtime(t *testing.T) (*Runtime, string, string, string) {
	t.Helper()
	rt := newWorkspaceRuntime(t, "demo", "other")
	rt.cfg.Security.Commands = config.CommandRules{
		Deny:    []string{`--force`},
		Confirm: []string{`^git\b`},
		Default: "deny",
	}
	auditLogger, err := audit.New(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	rt.audit = auditLogger
	workspace, ok := rt.reg.Get("demo")
	if !ok {
		t.Fatal("demo workspace not registered")
	}
	initIssue861Repository(t, workspace.Path, "repo", true)
	opened := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{"action": "open", "workspace": "demo"})
	if !statusOK(opened) {
		t.Fatalf("open issue 861 session: %+v", opened)
	}
	return rt, stringValue(opened["remote_session_id"]), workspace.Path, auditLogger.Path()
}

func initIssue861Repository(t *testing.T, workspace, name string, withRemote bool) {
	t.Helper()
	repo := filepath.Join(workspace, name)
	if err := os.MkdirAll(filepath.Join(repo, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	runIssue861Git(t, workspace, "init", name)
	runIssue861Git(t, workspace, "-C", name, "config", "user.email", "issue-861@example.invalid")
	runIssue861Git(t, workspace, "-C", name, "config", "user.name", "Issue 861 Test")
	runIssue861Git(t, workspace, "-C", name, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(repo, "docs", "allowed.md"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "other.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runIssue861Git(t, workspace, "-C", name, "add", "--", "docs/allowed.md", "other.txt")
	runIssue861Git(t, workspace, "-C", name, "commit", "-m", "fixture")
	runIssue861Git(t, workspace, "-C", name, "switch", "-c", "feat/issue-861")
	if !withRemote {
		return
	}
	remoteName := "remote.git"
	remotePath := filepath.Join(workspace, remoteName)
	command := exec.Command("git", "init", "--bare", remotePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, output)
	}
	runIssue861Git(t, workspace, "-C", name, "remote", "add", "origin", filepath.ToSlash(remotePath))
}

func runIssue861Git(t *testing.T, workDir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = workDir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func createIssue861Grant(t *testing.T, rt *Runtime, remoteID string) string {
	t.Helper()
	request := map[string]any{
		"action":                   "run",
		"remote_session_id":        remoteID,
		"purpose":                  issue861Purpose,
		"command":                  "git -C repo status --short",
		"scope":                    "workspace",
		"authorization_context_id": issue861ContextID,
		"authorization_request": map[string]any{
			"work_package_id":    "issue-861",
			"work_package_goal":  "Implement bounded conversation authorization",
			"purpose_patterns":   []string{"issue 861*"},
			"action_classes":     []string{"git_read", "git_remote_read", "git_local_write", "git_remote_write", "git_cleanup"},
			"repositories":       []string{"workspace:repo", "workspace:remote.git"},
			"targets":            []string{"branch:feat/*", "remote:origin:feat/*"},
			"write_paths":        []string{"repo/docs/**"},
			"risk_ceiling":       "ordinary",
			"expires_in_seconds": 3600,
		},
	}
	waiting := callEnvelope(t, rt.toolExecute, context.Background(), request)
	if waiting["status"] != "waiting_confirmation" || errorCode(waiting) != "user_confirmation_required" {
		t.Fatalf("initial bounded authorization did not require one confirmation: %+v", waiting)
	}
	waitingAuthorization := responseData(t, waiting)["authorization"].(map[string]any)
	if waitingAuthorization["decision"] != "authorization_request_pending" || waitingAuthorization["matched"] != true {
		t.Fatalf("authorization request was not bound to the initiating command: %+v", waitingAuthorization)
	}

	confirmedRequest := cloneMap(request)
	confirmedRequest["user_confirmed"] = true
	confirmed := callEnvelope(t, rt.toolExecute, context.Background(), confirmedRequest)
	if !statusOK(confirmed) {
		t.Fatalf("confirmed bounded authorization did not execute: %+v", confirmed)
	}
	authorization := responseData(t, confirmed)["authorization"].(map[string]any)
	if authorization["decision"] != "grant_created" || authorization["matched"] != true {
		t.Fatalf("confirmed authorization did not create an active grant: %+v", authorization)
	}
	grant, _ := authorization["grant"].(map[string]any)
	grantID := stringValue(grant["grant_id"])
	if grantID == "" || grant["status"] != "active" || grant["authorization_context_id"] != issue861ContextID {
		t.Fatalf("invalid created grant: %+v", grant)
	}
	return grantID
}

func runIssue861AuthorizedCommand(t *testing.T, rt *Runtime, remoteID, grantID, contextID, purpose, command string) map[string]any {
	t.Helper()
	return callEnvelope(t, rt.toolExecute, context.Background(), map[string]any{
		"action":                   "run",
		"remote_session_id":        remoteID,
		"purpose":                  purpose,
		"command":                  command,
		"scope":                    "workspace",
		"authorization_context_id": contextID,
		"authorization_grant_id":   grantID,
	})
}

func assertIssue861GrantReuse(t *testing.T, response map[string]any, grantID string) {
	t.Helper()
	if !statusOK(response) {
		t.Fatalf("grant-backed command did not execute: %+v", response)
	}
	authorization := responseData(t, response)["authorization"].(map[string]any)
	if authorization["decision"] != "grant_reused" || authorization["matched"] != true || authorization["grant_reused"] != true {
		t.Fatalf("command did not reuse grant: %+v", authorization)
	}
	source, _ := authorization["grant_source"].(map[string]any)
	if source["grant_id"] != grantID {
		t.Fatalf("wrong grant source: %+v", authorization)
	}
}

func assertIssue861NeedsConfirmation(t *testing.T, response map[string]any, reason string) {
	t.Helper()
	if response["status"] != "waiting_confirmation" || errorCode(response) != "user_confirmation_required" {
		t.Fatalf("boundary change did not return to confirmation: %+v", response)
	}
	authorization, _ := responseData(t, response)["authorization"].(map[string]any)
	if authorization["matched"] == true || !jsonStringSliceContains(authorization["match_reasons"], reason) {
		t.Fatalf("confirmation did not explain boundary mismatch %q: %+v", reason, authorization)
	}
	if authorization["grant_reused"] == true || authorization["grant_used_for_confirmation_bypass"] == true {
		t.Fatalf("boundary mismatch was incorrectly audited as grant reuse: %+v", authorization)
	}
}

func responseData(t *testing.T, response map[string]any) map[string]any {
	t.Helper()
	data, ok := response["data"].(map[string]any)
	if !ok {
		t.Fatalf("response data missing or invalid: %+v", response)
	}
	return data
}

func grantListContains(raw any, grantID string) bool {
	items, _ := raw.([]any)
	for _, item := range items {
		grant, _ := item.(map[string]any)
		if grant["grant_id"] == grantID {
			return true
		}
	}
	return false
}

func readIssue861Audit(t *testing.T, path string) []map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode authorization audit: %v: %s", err, line)
		}
		events = append(events, event)
	}
	return events
}

func jsonStringSliceContains(raw any, expected string) bool {
	switch values := raw.(type) {
	case []any:
		for _, value := range values {
			if value == expected {
				return true
			}
		}
	case []string:
		for _, value := range values {
			if value == expected {
				return true
			}
		}
	}
	return false
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
