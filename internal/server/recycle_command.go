package server

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"mcpx/internal/winproc"
)

// The path is child-process data, never PowerShell source or a trailing -Command argument.
const recycleTargetEnv = "MCPX_RECYCLE_TARGET"
const recycleWindowsScript = `$ErrorActionPreference='Stop'
try {
 Add-Type -AssemblyName Microsoft.VisualBasic
 $p=[Environment]::GetEnvironmentVariable('MCPX_RECYCLE_TARGET','Process')
 if ([string]::IsNullOrWhiteSpace($p)) { throw [ArgumentException]::new('missing recycle target') }
 $entry=Get-Item -LiteralPath $p -Force
 if ($entry.PSIsContainer) {
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p,[Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,[Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,[Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
 } else {
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p,[Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,[Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,[Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
 }
} catch {
 $e=$_.Exception
 while ($null -ne $e.InnerException) { $e=$e.InnerException }
 @{exception=$e.GetType().FullName;hresult=$e.HResult} | ConvertTo-Json -Compress
 exit 1
}`

func recycleWindowsTarget(parent context.Context, workDir, source string) error {
	// Cold PowerShell/assembly startup must not consume the two-second read-probe budget.
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	name := "powershell.exe"
	path, err := exec.LookPath(name)
	if errors.Is(err, exec.ErrNotFound) {
		name = "pwsh.exe"
		path, err = exec.LookPath(name)
	}
	if err != nil {
		return fmt.Errorf("recycle executable unavailable: %w", err)
	}
	units := utf16.Encode([]rune(recycleWindowsScript))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	cmd := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	winproc.ConfigureNoWindow(cmd)
	cmd.Dir = workDir
	for _, variable := range os.Environ() {
		key, _, _ := strings.Cut(variable, "=")
		if !strings.EqualFold(key, recycleTargetEnv) {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, recycleTargetEnv+"="+source)
	// PowerShell may emit CLIXML progress on stderr even when stdout is valid JSON.
	output, runErr := cmd.Output()
	if ctx.Err() != nil {
		return fmt.Errorf("recycle interrupted; outcome must be inspected: %w", ctx.Err())
	}
	if runErr == nil {
		return nil
	}
	// Return OS diagnostics without echoing arbitrary PowerShell output, paths or environment.
	var diagnostic struct {
		Exception string `json:"exception"`
		HResult   int64  `json:"hresult"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(string(output))), &diagnostic) == nil && diagnostic.Exception != "" {
		return fmt.Errorf("%s recycle failed: %s (HRESULT 0x%08X)", name, diagnostic.Exception, uint32(diagnostic.HResult))
	}
	return fmt.Errorf("%s recycle failed: %w", name, runErr)
}
