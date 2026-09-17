package server

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Opt-in acceptance against the existing PR branch. It never creates commits
// or changes the remote branch: push sends the same fetched commit back.
func TestGitHubCLIHelperNormalHomeNetworkAcceptance(t *testing.T) {
	if runtime.GOOS != "windows" || os.Getenv("MCPX_TEST_REAL_GH_NETWORK") != "1" {
		t.Skip("requires explicit normal-HOME GitHub network acceptance")
	}
	const branch = "feat/issue-861-conversation-authorization-grants"
	rt, remoteID, workspace, _ := newIssue861Runtime(t)
	runIssue861Git(t, workspace, "-C", "repo", "remote", "set-url", "origin", "https://github.com/richarsun/mcpx.git")
	runIssue861Git(t, workspace, "-C", "repo", "fetch", "--no-tags", "origin", "refs/heads/"+branch)
	runIssue861Git(t, workspace, "-C", "repo", "switch", "-C", branch, "FETCH_HEAD")
	before := strings.TrimSpace(runIssue861Git(t, workspace, "-C", "repo", "rev-parse", "HEAD"))
	request := map[string]any{
		"action": "run", "remote_session_id": remoteID, "purpose": issue861Purpose,
		"command": "git -C repo status --short", "scope": "workspace",
		"authorization_context_id": issue861ContextID,
		"authorization_request": map[string]any{
			"work_package_id":   "issue-861-network-acceptance",
			"work_package_goal": "Verify normal HOME fetch and unchanged push on the existing PR branch",
			"purpose_patterns":  []string{"issue 861*"},
			"action_classes":    []string{"git_read", "git_remote_read", "git_remote_write"},
			"repositories":      []string{"workspace:repo", "github:richarsun/mcpx"},
			"targets":           []string{"branch:" + branch, "remote:origin:" + branch},
			"risk_ceiling":      "ordinary", "expires_in_seconds": 600,
		},
	}
	waiting := callEnvelope(t, rt.toolExecute, context.Background(), cloneMap(request))
	if waiting["status"] != "waiting_confirmation" {
		t.Fatalf("initial grant did not require confirmation: %+v", waiting)
	}
	request["user_confirmed"] = true
	confirmed := callEnvelope(t, rt.toolExecute, context.Background(), request)
	if !statusOK(confirmed) {
		t.Fatalf("grant creation failed: %+v", confirmed)
	}
	grant := responseData(t, confirmed)["authorization"].(map[string]any)["grant"].(map[string]any)
	grantID := stringValue(grant["grant_id"])
	var lastRequest map[string]any
	var lastTaskID string
	for _, operation := range []string{"fetch --no-tags --refmap=", "push"} {
		lastRequest = map[string]any{
			"action": "run", "remote_session_id": remoteID, "purpose": issue861Purpose,
			"command": "git -C repo " + operation + " origin " + branch, "scope": "workspace",
			"authorization_context_id": issue861ContextID, "authorization_grant_id": grantID,
			"idempotency_key": "normal-home-" + strings.Fields(operation)[0], "yield_time_ms": 1000,
		}
		response := callEnvelope(t, rt.toolExecute, context.Background(), cloneMap(lastRequest))
		if !statusOK(response) && response["status"] != "accepted" {
			t.Fatalf("network operation was not accepted: %+v", response)
		}
		data := responseData(t, response)
		authorization, _ := data["authorization"].(map[string]any)
		if authorization["decision"] != "grant_reused" || authorization["grant_used_for_confirmation_bypass"] != true || authorization["grant_id"] != grantID {
			t.Fatalf("network operation did not reuse the grant: %+v", authorization)
		}
		taskID := stringValue(data["execution_task_id"])
		lastTaskID = taskID
		deadline := time.Now().Add(45 * time.Second)
		for data["exit_code"] == nil && taskID != "" && time.Now().Before(deadline) {
			attached := callEnvelope(t, rt.toolExecute, context.Background(), map[string]any{
				"action": "attach", "remote_session_id": remoteID, "execution_task_id": taskID,
				"purpose": issue861Purpose, "yield_time_ms": 1000,
			})
			data = responseData(t, attached)
		}
		if data["exit_code"] != float64(0) {
			t.Fatalf("network %s did not exit successfully: %+v", operation, data)
		}
		t.Logf("normal HOME %s: grant_reused=true exit_code=0", operation)
	}
	remote := strings.Fields(runIssue861Git(t, workspace, "-C", "repo", "ls-remote", "origin", "refs/heads/"+branch))
	if len(remote) != 2 || remote[0] != before {
		t.Fatalf("remote branch changed during acceptance")
	}
	revoked := callEnvelope(t, rt.toolSession, context.Background(), map[string]any{
		"action": "authorization_revoke", "remote_session_id": remoteID, "purpose": issue861Purpose,
		"authorization_context_id": issue861ContextID, "authorization_grant_id": grantID,
		"authorization_reason": "normal HOME network acceptance completed",
	})
	if !statusOK(revoked) {
		t.Fatalf("revoke failed: %+v", revoked)
	}
	replay := callEnvelope(t, rt.toolExecute, context.Background(), cloneMap(lastRequest))
	replayData := responseData(t, replay)
	if (!statusOK(replay) && replay["status"] != "accepted") || replayData["idempotent_replay"] != true || stringValue(replayData["execution_task_id"]) != lastTaskID {
		t.Fatalf("completed push was not durably replayed after revoke: %+v", replay)
	}
	if lastTaskID != "" {
		attached := callEnvelope(t, rt.toolExecute, context.Background(), map[string]any{
			"action": "attach", "remote_session_id": remoteID, "execution_task_id": lastTaskID,
			"purpose": issue861Purpose, "yield_time_ms": 1000,
		})
		if responseData(t, attached)["exit_code"] != float64(0) {
			t.Fatalf("replayed task lost its completed result: %+v", attached)
		}
	}
	delete(lastRequest, "idempotency_key")
	postRevoke := callEnvelope(t, rt.toolExecute, context.Background(), lastRequest)
	assertIssue861NeedsConfirmation(t, postRevoke, "grant_status:revoked")
	t.Log("remote unchanged; revoke blocks new push; completed push replays without re-execution")
}
