package server

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcpx/internal/mcpresult"
)

// 验证实际对外注册的字段，避免只测试内部handler而遗漏工具声明。
func TestIssue823PublishedExecuteArguments(t *testing.T) {
	r := &Runtime{}
	r.registerTools(mcp.NewServer(&mcp.Implementation{Name: "mcpx-test", Version: "0.1.0"}, nil))
	var schema map[string]any
	if err := json.Unmarshal(mcpresult.ToolSchemaJSON(r.listedToolMap()["execute"]), &schema); err != nil {
		t.Fatal(err)
	}
	root := schema["properties"].(map[string]any)
	for _, name := range []string{"argv", "shell", "expected_workspace", "workspace_transition"} {
		if root[name] == nil {
			t.Fatalf("公开execute缺少字段 %s", name)
		}
	}
	t.Logf("实际注册工具schema revision: %s", r.currentToolSchemaRevision())
}
