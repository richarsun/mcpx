//go:build windows

package terminal

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 验证真实 Python 子进程收到完整源码、中文空格参数和空参数。
func TestWindowsShellQuotedPythonArguments(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("本机没有现成 Python，不安装依赖")
	}
	command := `python -X utf8 -c "import json,sys; print(json.dumps(sys.argv[1:], ensure_ascii=False))" "中文 空格" "" "普通参数"`
	output, err := commandShell(context.Background(), command).CombinedOutput()
	if err != nil {
		t.Fatalf("实际 Python 命令失败: %v\n%s", err, output)
	}
	if got, want := strings.TrimSpace(string(output)), `["中文 空格", "", "普通参数"]`; got != want {
		t.Fatalf("参数改变: got=%q want=%q", got, want)
	}
}

// 覆盖带空格和中文的可执行路径，以及调用方本来就要求的Shell组合语义。
func TestWindowsShellQuotedBatchPathAndOperators(t *testing.T) {
	path := filepath.Join(t.TempDir(), "中文 脚本.cmd")
	if err := os.WriteFile(path, []byte("@echo off\r\necho %~1\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := commandShell(context.Background(), `"`+path+`" "hello world" && echo tail`).CombinedOutput()
	if err != nil {
		t.Fatalf("实际批处理命令失败: %v\n%s", err, output)
	}
	if got, want := strings.TrimSpace(strings.ReplaceAll(string(output), "\r\n", "\n")), "hello world\ntail"; got != want {
		t.Fatalf("路径/参数/组合语义改变: got=%q want=%q", got, want)
	}
}
