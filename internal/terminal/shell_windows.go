//go:build windows

package terminal

import (
	"context"
	"os/exec"
	"syscall"

	"mcpx/internal/winproc"
)

func commandShell(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd")
	winproc.ConfigureNoWindow(cmd)
	// cmd.exe 不使用 Go 默认的 CommandLineToArgvW 反转义规则。
	// /s /c 移除包裹 command 的首尾引号，内部引号和 Shell 语法原样保留。
	cmd.SysProcAttr.CmdLine = syscall.EscapeArg(cmd.Path) + ` /s /c "` + command + `"`
	return cmd
}
