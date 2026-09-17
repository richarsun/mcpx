package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"mcpx/internal/winproc"
)

// Opt-in: only the disposable entries created by this test reach the real recycle bin.
func TestMoveOutWindowsRealRecycle(t *testing.T) {
	if runtime.GOOS != "windows" || os.Getenv("MCPX_TEST_REAL_RECYCLE") != "1" {
		t.Skip("requires Windows and MCPX_TEST_REAL_RECYCLE=1")
	}
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			rt := newWorkspaceRuntime(t, "demo")
			ws, _ := rt.reg.Get("demo")
			name := "issue860 中文 [literal] ' $ " + kind
			path := filepath.Join(ws.Path, name)
			content := []byte("issue860 disposable content\n")
			target := map[string]any{"path": name, "kind": kind}
			var outside string
			if kind == "symlink" {
				// Directory junctions do not require the symbolic-link privilege on Windows.
				outside = t.TempDir()
				if err := os.WriteFile(filepath.Join(outside, "content.txt"), content, 0o600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:MCPX_TEST_LINK -Target $env:MCPX_TEST_LINK_TARGET | Out-Null`)
				winproc.ConfigureNoWindow(cmd)
				cmd.Env = append(os.Environ(), "MCPX_TEST_LINK="+path, "MCPX_TEST_LINK_TARGET="+outside)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("create isolated junction: %v: %s", err, output)
				}
			} else if kind == "directory" {
				if err := os.MkdirAll(filepath.Join(path, "nested"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "nested", "content.txt"), content, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
				target["expected_sha256"] = digestForTest(content)
			}
			remoteID := openMoveOutSession(t, rt)
			prepared := callMoveOut(t, rt.toolMoveOut, map[string]any{"action": "prepare", "remote_session_id": remoteID, "purpose": "将本测试创建的临时对象移入系统回收站", "targets": []any{target}})
			if kind == "symlink" {
				// Go exposes junctions as irregular entries; preserve the existing fail-closed gate.
				errorData, _ := prepared["error"].(map[string]any)
				if errorData["code"] != "MOVE_OUT_FILE_ONLY" {
					t.Fatalf("junction not rejected by existing target gate: %+v", prepared)
				}
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf("rejected junction mutated: %v", err)
				}
				if actual, err := os.ReadFile(filepath.Join(outside, "content.txt")); err != nil || string(actual) != string(content) {
					t.Fatalf("junction target mutated: %v", err)
				}
				return
			}
			if !statusOK(prepared) {
				t.Fatalf("prepare: %+v", prepared)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("prepare mutated source: %v", err)
			}
			args := moveOutCommitArguments(remoteID, prepared["data"].(map[string]any))
			result := callMoveOut(t, rt.toolMoveOut, args)
			data, _ := result["data"].(map[string]any)
			if !statusOK(result) || data["moved_count"] != float64(1) || data["failed_count"] != float64(0) {
				t.Fatalf("real recycle failed: %+v", result)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("source remains: %v", err)
			}
			if data["reversible"] != true || !strings.HasPrefix(data["quarantine_location"].(string), "recycle-bin://") {
				t.Fatalf("not recoverable: %+v", data)
			}
			// Read the actual bin entry and payload; a missing source alone is not proof of recycling.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			query := `$ErrorActionPreference='Stop'; $p=$env:MCPX_TEST_RECYCLED_PATH; $shell=New-Object -ComObject Shell.Application; $bin=$shell.NameSpace(10); foreach($entry in $bin.Items()) { if ($entry.ExtendedProperty('System.Recycle.DeletedFrom') -eq [IO.Path]::GetDirectoryName($p) -and $entry.Name -eq [IO.Path]::GetFileName($p)) { [Console]::Write($entry.Path); exit 0 } }; exit 1`
			cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query)
			winproc.ConfigureNoWindow(cmd)
			cmd.Env = append(os.Environ(), "MCPX_TEST_RECYCLED_PATH="+path)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("cannot verify exact recycle entry: %v: %s", err, output)
			}
			payloadPath := strings.TrimSpace(string(output))
			if kind == "directory" {
				payloadPath = filepath.Join(payloadPath, "nested", "content.txt")
			}
			payload, err := os.ReadFile(payloadPath)
			if err != nil || string(payload) != string(content) {
				t.Fatalf("recycled payload mismatch: %v", err)
			}
			replay := callMoveOut(t, rt.toolMoveOut, args)
			if !statusOK(replay) || replay["data"].(map[string]any)["idempotent_replay"] != true {
				t.Fatalf("replay: %+v", replay)
			}
		})
	}
}

func TestRecycleWindowsTargetReportsDiagnostic(t *testing.T) {
	root := t.TempDir()
	err := recycleWindowsTarget(context.Background(), root, filepath.Join(root, "missing.txt"))
	if err == nil || !strings.Contains(err.Error(), "ItemNotFoundException") || !strings.Contains(err.Error(), "HRESULT 0x") {
		t.Fatalf("missing structured OS diagnostic: %v", err)
	}
	if strings.Contains(err.Error(), root) {
		t.Fatalf("diagnostic leaked source path: %v", err)
	}
}

func TestRecycleWindowsTargetCancellationPreservesSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "untouched.txt")
	if err := os.WriteFile(source, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := recycleWindowsTarget(ctx, root, source)
	if err == nil || !strings.Contains(err.Error(), "outcome must be inspected") {
		t.Fatalf("missing uncertain-outcome diagnostic: %v", err)
	}
	if content, readErr := os.ReadFile(source); readErr != nil || string(content) != "untouched" {
		t.Fatalf("cancelled command mutated source: %v", readErr)
	}
}

func TestMoveOutWindowsMissingShellReportsFailureWithoutMutation(t *testing.T) {
	rt := newWorkspaceRuntime(t, "demo")
	ws, _ := rt.reg.Get("demo")
	path := filepath.Join(ws.Path, "untouched.txt")
	content := []byte("preserve when recycle is unavailable")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	remoteID := openMoveOutSession(t, rt)
	prepared := callMoveOut(t, rt.toolMoveOut, map[string]any{"action": "prepare", "remote_session_id": remoteID, "purpose": "测试不可用回收入口", "targets": []any{map[string]any{"path": "untouched.txt", "kind": "file", "expected_sha256": digestForTest(content)}}})
	if !statusOK(prepared) {
		t.Fatalf("prepare: %+v", prepared)
	}
	t.Setenv("PATH", t.TempDir())
	args := moveOutCommitArguments(remoteID, prepared["data"].(map[string]any))
	result := callMoveOut(t, rt.toolMoveOut, args)
	data, ok := result["data"].(map[string]any)
	if !ok || data["moved_count"] != float64(0) || data["failed_count"] != float64(1) {
		t.Fatalf("failure counts: %+v", result)
	}
	target := data["target_preview"].([]any)[0].(map[string]any)
	if target["error_code"] != "MOVE_OUT_FAILED" || !strings.Contains(target["error_message"].(string), "recycle executable unavailable") {
		t.Fatalf("missing public diagnostic: %+v", target)
	}
	if actual, err := os.ReadFile(path); err != nil || string(actual) != string(content) {
		t.Fatalf("failed recycle mutated source: %v", err)
	}
	replay := callMoveOut(t, rt.toolMoveOut, args)
	replayData, _ := replay["data"].(map[string]any)
	if replayData["idempotent_replay"] != true || replayData["failed_count"] != float64(1) {
		t.Fatalf("failed outcome not replayed: %+v", replay)
	}
}
