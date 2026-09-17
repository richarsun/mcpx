package authorization

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// 仅显式启用时读取正常 HOME 的 helper 配置；不读取凭据、不执行网络操作。
func TestGitHubCLIHelperNormalHome(t *testing.T) {
	if runtime.GOOS != "windows" || os.Getenv("MCPX_TEST_REAL_GH_HELPER") != "1" {
		t.Skip("正常 Windows HOME 验收需显式启用")
	}
	workspace, repo := newGitFixture(t)
	runGit(t, repo, "remote", "set-url", "origin", "https://github.com/owner/repo.git")
	for _, command := range []string{
		"git -C repo fetch --no-tags --refmap= origin main",
		"git -C repo push origin feat/issue-861",
	} {
		action := ClassifyCommand(context.Background(), workspace, []string{command})
		if !action.Eligible {
			t.Fatalf("正常 HOME 的已支持 GitHub CLI helper 被拒绝: %v", action.Reasons)
		}
		assertContains(t, action.Repositories, "github:owner/repo")
	}
}

func TestGitHubCLIHelperScopedChain(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("GitHub CLI helper 正向支持仅限 Windows")
	}
	gh, err := exec.LookPath("gh")
	if err != nil {
		t.Skip("未安装 GitHub CLI")
	}
	gh, err = filepath.Abs(gh)
	if err != nil {
		t.Fatal(err)
	}
	helper := "!'" + gh + "' auth git-credential"
	const key = "credential.https://github.com.helper"
	replaceHelper := func(t *testing.T, repo, value string) {
		runGit(t, repo, "config", "--global", "--unset-all", key)
		runGit(t, repo, "config", "--global", "--add", key, "")
		runGit(t, repo, "config", "--global", "--add", key, value)
	}
	for _, test := range []struct {
		name     string
		change   func(t *testing.T, repo string)
		eligible bool
	}{
		{name: "正常 reset 与固定 gh", eligible: true},
		{name: "gist 同型配置共存", eligible: true, change: func(t *testing.T, repo string) {
			runGit(t, repo, "config", "--global", "--add", "credential.https://gist.github.com.helper", "")
			runGit(t, repo, "config", "--global", "--add", "credential.https://gist.github.com.helper", helper)
		}},
		{name: "缺少 reset", change: func(t *testing.T, repo string) { runGit(t, repo, "config", "--global", "--replace-all", key, helper) }},
		{name: "追加 shell", change: func(t *testing.T, repo string) {
			replaceHelper(t, repo, helper+" && echo marker")
		}},
		{name: "第三个 helper", change: func(t *testing.T, repo string) { runGit(t, repo, "config", "--global", "--add", key, "manager") }},
		{name: "本地重定义", change: func(t *testing.T, repo string) {
			runGit(t, repo, "config", "--add", key, "")
			runGit(t, repo, "config", "--add", key, helper)
		}},
		{name: "其他 URL", change: func(t *testing.T, repo string) {
			runGit(t, repo, "config", "--global", "credential.https://example.com.helper", helper)
		}},
		{name: "更具体 URL", change: func(t *testing.T, repo string) {
			runGit(t, repo, "config", "--global", "credential.https://github.com/owner.helper", helper)
		}},
		{name: "其他 executable", change: func(t *testing.T, repo string) {
			replaceHelper(t, repo, "!'C:/temp/gh.exe' auth git-credential")
		}},
		{name: "额外参数", change: func(t *testing.T, repo string) {
			replaceHelper(t, repo, helper+" --hostname other.example")
		}},
		{name: "顺序反转", change: func(t *testing.T, repo string) {
			runGit(t, repo, "config", "--global", "--unset-all", key)
			runGit(t, repo, "config", "--global", "--add", key, helper)
			runGit(t, repo, "config", "--global", "--add", key, "")
		}},
		{name: "include 来源", change: func(t *testing.T, repo string) {
			included := filepath.Join(t.TempDir(), "included.config")
			runGit(t, repo, "config", "--global", "--unset-all", key)
			runGit(t, repo, "config", "--file", included, "--add", key, "")
			runGit(t, repo, "config", "--file", included, "--add", key, helper)
			runGit(t, repo, "config", "--global", "include.path", included)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			workspace, repo := newGitFixture(t)
			runGit(t, repo, "remote", "set-url", "origin", "https://github.com/owner/repo.git")
			runGit(t, repo, "config", "--global", "--add", key, "")
			runGit(t, repo, "config", "--global", "--add", key, helper)
			if test.change != nil {
				test.change(t, repo)
			}
			action := ClassifyCommand(context.Background(), workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
			if action.Eligible != test.eligible {
				t.Fatalf("Eligible=%v want=%v reasons=%v", action.Eligible, test.eligible, action.Reasons)
			}
		})
	}
}
