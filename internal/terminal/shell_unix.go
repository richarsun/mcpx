//go:build !windows

package terminal

import (
	"context"
	"os/exec"
)

func commandShell(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, ExecutionShell(), "-lc", command)
}
