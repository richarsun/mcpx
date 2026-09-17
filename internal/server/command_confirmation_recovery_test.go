package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 使用公开 Schema 返回的模板恢复，防止测试手动补齐 Runtime 丢失的参数。
func TestCommandConfirmationRecoveryThroughPublicSchema(t *testing.T) {
	for _, mode := range []string{"command", "argv", "task"} {
		t.Run(mode, func(t *testing.T) {
			rt := newWorkspaceRuntime(t, "恢复测试")
			s := operationTestSession(t, rt, "恢复测试")
			rt.cfg.Security.Commands.Default = "confirm"
			rt.cfg.Security.Commands.Allow = nil
			protocol := mcp.NewServer(&mcp.Implementation{Name: "command-recovery", Version: "test"}, nil)
			rt.registerTools(protocol)
			server := httptest.NewServer(NewGateway(rt.cfg, nil, mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return protocol }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true, Stateless: true})).Handler())
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			client, err := mcp.NewClient(&mcp.Implementation{Name: "recovery-client", Version: "test"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			call := func(args map[string]any) map[string]any {
				t.Helper()
				result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "execute", Arguments: args})
				if err != nil {
					t.Fatal(err)
				}
				return decodeToolResult(t, result)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(s.WorkspacePath, "effect.jsonl")
			request := map[string]any{
				"action": "run", "remote_session_id": s.ID, "purpose": "验证原请求确认恢复",
				"idempotency_key": "command-recovery-" + mode, "execution_mode": "sync",
				"activity": map[string]any{"next": "验证确认恢复"}, "yield_time_ms": 10000,
			}
			switch mode {
			case "command":
				request["command"] = fmt.Sprintf(`"%s" -test.run=^TestIssue823ArgvChild$ -- --issue823-argv-child "%s" "一次" && echo recovered`, executable, output)
			case "argv":
				request["argv"] = []any{executable, "-test.run=^TestIssue823ArgvChild$", "--", "--issue823-argv-child", output, "一次"}
				request["shell"] = false
			case "task":
				if err := os.WriteFile(filepath.Join(s.WorkspacePath, "go.mod"), []byte("module recovery\n\ngo 1.26.1\n"), 0600); err != nil {
					t.Fatal(err)
				}
				request["task"] = "test"
			}
			waiting := call(request)
			if waiting["status"] != "waiting_confirmation" {
				t.Fatalf("未等待确认: %+v", waiting)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("确认前产生执行效果")
			}
			recovery := waiting["error"].(map[string]any)["recovery"].(map[string]any)
			retry := recovery["arguments"].(map[string]any)
			want := cloneMap(request)
			want["user_confirmed"] = true
			wantJSON, _ := json.Marshal(want)
			gotJSON, _ := json.Marshal(retry)
			if string(wantJSON) != string(gotJSON) {
				t.Fatalf("恢复模板改变原请求:\n原请求=%s\n恢复=%s", wantJSON, gotJSON)
			}
			if mode == "task" {
				return
			} // 任务发现与公开模板保真，不启动额外构建。
			changed := cloneMap(retry)
			changed["purpose"] = "不同的执行目的"
			if result := call(changed); result["status"] != "waiting_confirmation" {
				t.Fatalf("目的改变后复用旧确认: %+v", result)
			}
			originalDeny := rt.cfg.Security.Commands.Deny
			rt.cfg.Security.Commands.Deny = []string{`.*`}
			denied := call(retry)
			rt.cfg.Security.Commands.Deny = originalDeny
			if statusOK(denied) || denied["status"] == "waiting_confirmation" {
				t.Fatalf("确认模板绕过拒绝策略: %+v", denied)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("目的变更或拒绝策略下产生执行效果")
			}
			first := call(retry)
			if !statusOK(first) || first["data"].(map[string]any)["exit_code"] != float64(0) {
				t.Fatalf("确认恢复失败: %+v", first)
			}
			taskID := first["data"].(map[string]any)["execution_task_id"]
			// 成功后分别重放返回模板与调用方保存的原请求。
			for _, replayArgs := range []map[string]any{retry, want} {
				replay := call(replayArgs)
				if !statusOK(replay) || replay["data"].(map[string]any)["idempotent_replay"] != true || replay["data"].(map[string]any)["execution_task_id"] != taskID {
					t.Fatalf("未回读同一执行结果: %+v", replay)
				}
			}
			content, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var effect []string
			if err := json.Unmarshal(content, &effect); err != nil || !reflect.DeepEqual(effect, []string{"一次"}) {
				t.Fatalf("执行效果不唯一或参数漂移: %q, %v", content, err)
			}
		})
	}
}
