package authorization

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestClassifyBoundedGitWorkPackage(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := withPullRequestMetadataResolver(context.Background(), func(context.Context, string, string) (pullRequestMetadata, error) {
		return pullRequestMetadata{BaseRefName: "main", HeadRefName: "feat/issue-861"}, nil
	})
	ctx = withGrantTestExecutables(t, ctx)
	now := time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)

	writeFile(t, filepath.Join(repo, "docs", "new.md"), "new\n")
	runGit(t, repo, "add", "--", "docs/new.md")

	tests := []struct {
		name       string
		command    string
		class      string
		repository string
		target     string
		writePath  string
	}{
		{
			name:       "read status",
			command:    "git -C repo status --short",
			class:      "git_read",
			repository: "workspace:repo",
		},
		{
			name:       "read diff",
			command:    "git -C repo diff --no-ext-diff --no-textconv -- docs/allowed.md",
			class:      "git_read",
			repository: "workspace:repo",
		},
		{
			name:       "read log",
			command:    "git -C repo log -1 --oneline",
			class:      "git_read",
			repository: "workspace:repo",
		},
		{
			name:       "read show",
			command:    "git -C repo show --no-ext-diff --no-textconv --oneline --stat HEAD",
			class:      "git_read",
			repository: "workspace:repo",
		},
		{
			name:       "read rev-parse",
			command:    "git -C repo rev-parse --show-toplevel",
			class:      "git_read",
			repository: "workspace:repo",
		},
		{
			name:       "read current branch",
			command:    "git -C repo branch --show-current",
			class:      "git_read",
			repository: "workspace:repo",
			target:     "branch:feat/issue-861",
		},
		{
			name:       "remote fetch",
			command:    "git -C repo fetch --no-tags --refmap= origin main",
			class:      "git_remote_read",
			repository: "workspace:remote.git",
			target:     "remote:origin:main",
		},
		{
			name:       "create branch at current head",
			command:    "git -C repo switch -c feat/next",
			class:      "git_local_write",
			repository: "workspace:repo",
			target:     "branch:feat/next",
		},
		{
			name:       "switch existing branch",
			command:    "git -C repo switch main",
			class:      "git_local_write",
			repository: "workspace:repo",
			target:     "branch:main",
			writePath:  "repo/**",
		},
		{
			name:       "stage explicit path",
			command:    "git -C repo add -- docs/new.md",
			class:      "git_local_write",
			repository: "workspace:repo",
			writePath:  "repo/docs/new.md",
		},
		{
			name:       "commit staged domain",
			command:    "git -C repo commit -m issue-861",
			class:      "git_local_write",
			repository: "workspace:repo",
			target:     "branch:feat/issue-861",
			writePath:  "repo/docs/new.md",
		},
		{
			name:       "commit with cross-platform double-quoted message",
			command:    `git -C repo commit -m "issue 861"`,
			class:      "git_local_write",
			repository: "workspace:repo",
			target:     "branch:feat/issue-861",
			writePath:  "repo/docs/new.md",
		},
		{
			name:       "push feature branch",
			command:    "git -C repo push origin feat/issue-861",
			class:      "git_remote_write",
			repository: "workspace:remote.git",
			target:     "remote:origin:feat/issue-861",
		},
		{
			name:       "safe branch cleanup",
			command:    "git -C repo branch -d old-topic",
			class:      "git_cleanup",
			repository: "workspace:repo",
			target:     "branch:old-topic",
		},
		{
			name:       "create pull request",
			command:    "gh pr create --repo richarsun/mcpx --base main --head feat/issue-861 --title issue-861 --body bounded-change",
			class:      "github_pr_write",
			repository: "github:richarsun/mcpx",
			target:     "pr:richarsun/mcpx:create",
		},
		{
			name:       "view explicit pull request",
			command:    "gh pr view 861 --repo richarsun/mcpx",
			class:      "git_remote_read",
			repository: "github:richarsun/mcpx",
			target:     "pr:richarsun/mcpx#861",
		},
		{
			name:       "merge explicit pull request",
			command:    "gh pr merge 861 --repo richarsun/mcpx --merge",
			class:      "github_pr_merge",
			repository: "github:richarsun/mcpx",
			target:     "pr:richarsun/mcpx#861",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := ClassifyCommand(ctx, workspace, []string{test.command})
			if !action.Eligible || action.Risk != RiskOrdinary {
				t.Fatalf("expected ordinary eligible action: %+v", action)
			}
			if !filepath.IsAbs(action.Executable) || len(action.Arguments) == 0 {
				t.Fatalf("eligible action did not pin an executable and argv: %+v", action)
			}
			if action.Environment == nil {
				t.Fatalf("eligible action did not freeze its execution environment: %+v", action)
			}
			if len(action.Repositories) == 0 {
				t.Fatalf("eligible action escaped repository scoping: %+v", action)
			}
			if test.class == "git_read" && len(action.Targets) == 0 {
				t.Fatalf("grant-eligible git_read escaped target scoping: %+v", action)
			}
			assertContains(t, action.Classes, test.class)
			assertContains(t, action.Repositories, test.repository)
			if test.target != "" {
				assertContains(t, action.Targets, test.target)
			}
			if test.writePath != "" {
				assertContains(t, action.WritePaths, test.writePath)
			}
		})
	}

	scope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses: []string{
			"git_read", "git_remote_read", "git_local_write", "git_remote_write",
			"github_pr_write", "github_pr_merge", "git_cleanup",
		},
		Repositories: []string{"workspace:repo", "workspace:remote.git", "github:richarsun/mcpx"},
		Targets: []string{
			"branch:main", "branch:feat/*", "branch:old-topic",
			"remote:origin:main", "remote:origin:feat/*", "pr:richarsun/mcpx*",
		},
		WritePaths:  []string{"repo/docs/**"},
		RiskCeiling: RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{Status: StatusActive, Scope: scope, ExpiresAt: now.Add(time.Hour)}
	for _, command := range []string{
		"git -C repo status --short",
		"git -C repo diff --no-ext-diff --no-textconv -- docs/allowed.md",
		"git -C repo fetch --no-tags --refmap= origin main",
		"git -C repo switch -c feat/matcher",
		"git -C repo add -- docs/new.md",
		"git -C repo commit -m issue-861",
		"git -C repo push origin feat/issue-861",
		"git -C repo branch -d old-topic",
		"gh pr create --repo richarsun/mcpx --base main --head feat/issue-861 --title issue-861 --body bounded-change",
		"gh pr view 861 --repo richarsun/mcpx",
		"gh pr merge 861 --repo richarsun/mcpx --merge",
	} {
		action := ClassifyCommand(ctx, workspace, []string{command})
		match := Match(grant, "issue 861 implementation", action, now)
		if !match.Matched {
			t.Fatalf("bounded work-package command did not match: %s => %+v", command, match)
		}
	}
}

func TestClassifierUsesParsedGitHubRepositoryOption(t *testing.T) {
	workspace, _ := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())
	action := ClassifyCommand(ctx, workspace, []string{`gh pr create --title "--repo=allowed/repo" --repo other/repo --base main --head feat/topic --body bounded-change`})
	if !action.Eligible {
		t.Fatalf("explicit gh repository was not classified: %+v", action)
	}
	assertContains(t, action.Repositories, "github:other/repo")
	for _, repository := range action.Repositories {
		if repository == "github:allowed/repo" {
			t.Fatalf("title value was misparsed as --repo: %+v", action)
		}
	}
}

func TestClassifierRejectsCompoundCommandsAndEdgeWhitespacePaths(t *testing.T) {
	workspace, _ := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())

	compound := ClassifyCommand(ctx, workspace, []string{
		"git -C repo add -- docs/allowed.md",
		"git -C repo status --short",
	})
	if compound.Eligible {
		t.Fatalf("compound command became grant eligible: %+v", compound)
	}
	assertContains(t, compound.Reasons, "compound_commands_not_grant_eligible")

	edgeWhitespace := ClassifyCommand(ctx, workspace, []string{`git -C repo add -- "docs/allowed.md "`})
	if edgeWhitespace.Eligible {
		t.Fatalf("edge-whitespace path became grant eligible: %+v", edgeWhitespace)
	}
}

func TestMatchPreservesWritePathEdgeWhitespace(t *testing.T) {
	scope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses:   []string{"git_local_write"},
		Repositories:    []string{"workspace:repo"},
		WritePaths:      []string{"repo/docs/allowed.md"},
		RiskCeiling:     RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 15, 6, 0, 0, 0, time.UTC)
	match := Match(Grant{Status: StatusActive, Scope: scope, ExpiresAt: now.Add(time.Hour)}, "issue 861 implementation", Action{
		Eligible:     true,
		Risk:         RiskOrdinary,
		Classes:      []string{"git_local_write"},
		Repositories: []string{"workspace:repo"},
		WritePaths:   []string{"repo/docs/allowed.md "},
	}, now)
	if match.Matched {
		t.Fatalf("edge-whitespace write path collapsed into an authorized path: %+v", match)
	}
	assertContains(t, match.Reasons, "write_path_out_of_scope:repo/docs/allowed.md ")
}

func TestClassifierRejectsGitReadExternalExecutionSurfaces(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())

	for _, command := range []string{
		"git -C repo log -1",
		"git -C repo log -1 --oneline --oneline",
		"git -C repo diff --no-ext-diff --src-prefix --no-textconv HEAD",
		"git -C repo show --no-ext-diff --no-textconv --stat HEAD",
		"git -C repo show --no-ext-diff --src-prefix --no-textconv --oneline HEAD",
		"git -C repo show --no-ext-diff --no-textconv --oneline --src-prefix=prefix/ --stat HEAD",
		"git -C repo show --no-ext-diff --no-textconv --oneline --show-signature --stat HEAD",
		"git -C repo show --no-ext-diff --no-textconv --oneline --patch --stat HEAD",
		"git -C repo show --no-ext-diff --no-textconv --oneline --stat HEAD extra",
		"git -C repo show --no-ext-diff --no-textconv --oneline --oneline --stat HEAD",
		"git -C repo diff --no-ext-diff --no-textconv -- /etc/passwd",
		"git -C repo show --no-ext-diff --no-textconv --oneline --stat /etc/passwd",
		"git -C repo diff --no-ext-diff --no-textconv -- //server/share",
	} {
		action := ClassifyCommand(ctx, workspace, []string{command})
		if action.Eligible {
			t.Fatalf("git read option changed the execution surface but became eligible: %s => %+v", command, action)
		}
	}

	runGit(t, repo, "config", "log.showSignature", "true")
	for _, command := range []string{
		"git -C repo log -1 --oneline",
		"git -C repo show --no-ext-diff --no-textconv --oneline --stat HEAD",
	} {
		action := ClassifyCommand(ctx, workspace, []string{command})
		if action.Eligible {
			t.Fatalf("implicit signature verification became grant eligible: %s => %+v", command, action)
		}
	}

	runGit(t, repo, "config", "log.showSignature", "false")
	runGit(t, repo, "config", "format.pretty", "format:%G?")
	for _, command := range []string{
		"git -C repo log -1 --oneline",
		"git -C repo show --no-ext-diff --no-textconv --oneline --stat HEAD",
	} {
		action := ClassifyCommand(ctx, workspace, []string{command})
		if !action.Eligible {
			t.Fatalf("explicit built-in oneline format was rejected: %s => %+v", command, action)
		}
	}

	runGit(t, repo, "config", "diff.issue861.textconv", "external-helper")
	writeFile(t, filepath.Join(repo, ".gitattributes"), "docs/allowed.md diff=issue861\n")
	runGit(t, repo, "add", "--", ".gitattributes")
	runGit(t, repo, "commit", "-m", "activate show textconv")
	action := ClassifyCommand(ctx, workspace, []string{"git -C repo show --no-ext-diff --no-textconv --oneline --stat HEAD"})
	if action.Eligible {
		t.Fatalf("show with active external diff attributes became grant eligible: %+v", action)
	}
}

func TestClassifierAndMatcherFailClosedOnBoundaryChanges(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)
	writeFile(t, filepath.Join(repo, "other.txt"), "changed\n")

	scope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses:   []string{"git_read", "git_local_write", "git_remote_write"},
		Repositories:    []string{"workspace:repo", "workspace:remote.git"},
		Targets:         []string{"branch:feat/*", "remote:origin:feat/*"},
		WritePaths:      []string{"repo/docs/**"},
		RiskCeiling:     RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{Status: StatusActive, Scope: scope, ExpiresAt: now.Add(time.Hour)}

	outsideWrite := ClassifyCommand(ctx, workspace, []string{"git -C repo add -- other.txt"})
	match := Match(grant, "issue 861 implementation", outsideWrite, now)
	if match.Matched {
		t.Fatal("expanded write domain matched grant")
	}
	assertContains(t, match.Reasons, "write_path_out_of_scope:repo/other.txt")

	wholeWorktreeSwitch := ClassifyCommand(ctx, workspace, []string{"git -C repo switch main"})
	match = Match(grant, "issue 861 implementation", wholeWorktreeSwitch, now)
	if match.Matched {
		t.Fatal("existing-branch switch escaped narrow write domain")
	}
	assertContains(t, match.Reasons, "write_path_out_of_scope:repo/**")

	repoTwo := filepath.Join(workspace, "repo-two")
	if err := os.MkdirAll(repoTwo, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoTwo, "init")
	newRepository := ClassifyCommand(ctx, workspace, []string{"git -C repo-two status --short"})
	match = Match(grant, "issue 861 implementation", newRepository, now)
	if match.Matched {
		t.Fatal("new repository matched grant")
	}
	assertContains(t, match.Reasons, "repository_out_of_scope:workspace:repo-two")

	readAction := ClassifyCommand(ctx, workspace, []string{"git -C repo status --short"})
	match = Match(grant, "unrelated maintenance", readAction, now)
	if match.Matched {
		t.Fatal("changed purpose matched grant")
	}
	assertContains(t, match.Reasons, "purpose_out_of_scope")

	for _, command := range []string{
		"git -C repo push --force origin feat/issue-861",
		"git -C repo push origin",
		"git -C repo push origin refs/tags/v1",
		"git -C repo push origin HEAD:feat/issue-861",
		"git -C repo push origin missing:feat/issue-861",
		"git -C repo push origin feat/issue-861:develop",
		"git -C repo branch -D old-topic",
		"git -C repo branch --show-current -D old-topic",
		"git -C repo fetch origin",
		"git -C repo fetch --upload-pack=helper origin main",
		"git -C repo diff --output=outside.patch",
		"git -C repo diff --no-index ../outside.txt other.txt",
		"git -C repo add -- :/other.txt",
		"git -C repo add -- :(exclude)docs/allowed.md",
		"git -C repo add -- docs",
		"git -C repo commit -m scoped other.txt",
		"git -C repo commit -m scoped --trailer Reviewed-by=bot",
		"git -C repo commit -m scoped --trailer=Reviewed-by=bot",
		"git -C repo commit -v -m scoped",
		"git -C repo commit --verbose -m scoped",
		"git -C repo reset --hard HEAD~1",
		"git -C repo clean -fd",
		"git -C repo fetch origin main",
		"git -C repo fetch --no-tags origin main",
		"git -C repo fetch --no-tags --refmap= origin tag v1",
		"git -C repo diff --no-ext-diff --src-prefix --no-textconv HEAD",
		"git -C repo show --no-ext-diff --src-prefix --no-textconv HEAD",
		"git -C repo show --no-ext-diff --no-textconv --show-signature --stat HEAD",
		"git -C repo log -u -1",
		"git -C repo log --patch-with-stat -1",
		"git -C repo switch main -c feat/hidden-start",
		"git -C repo switch -c feat/hidden-start main",
		"gh pr create --base main --head feat/issue-861 --title issue-861 --body bounded-change",
		"gh pr view 861",
		"gh pr merge 861 --merge",
		"gh pr create --repo richarsun/mcpx --body-file ../../secret.txt",
		"gh pr edit 861 --repo richarsun/mcpx --title changed",
		"gh pr comment 861 --repo richarsun/mcpx --body note",
		"gh pr ready 861 --repo richarsun/mcpx",
		"git -C %USERPROFILE% status --short",
		"git -C $HOME status --short",
		"git -C ~ status --short",
		`git -C repo commit -m 'scoped message'`,
		`git -C repo add -- docs/*.md`,
		`git -C repo status --short (echo injected)`,
		"gh auth status",
		"gh secret set TOKEN --repo richarsun/mcpx",
		"go -C repo test ./... -count=1",
		"go -C repo test github.com/example/project",
		"go -C repo test ./... -coverprofile=../outside.cover",
		"kubectl apply -f production.yaml",
		"rm -rf repo",
		"python script.py",
		"git -C repo status | findstr M",
		"./git.sh -C repo status --short",
		"/tmp/git -C repo status --short",
		"git.exe -C repo status --short",
		"./gh pr view 861 --repo richarsun/mcpx",
	} {
		action := ClassifyCommand(ctx, workspace, []string{command})
		if action.Eligible {
			t.Fatalf("unsafe or unknown command became grant eligible: %s => %+v", command, action)
		}
		match = Match(grant, "issue 861 implementation", action, now)
		if match.Matched {
			t.Fatalf("unsafe or unknown command matched grant: %s => %+v", command, match)
		}
	}

	pathEscape := ClassifyCommand(ctx, workspace, []string{"git -C repo add -- ../../outside.txt"})
	if pathEscape.Eligible {
		t.Fatalf("workspace path escape became eligible: %+v", pathEscape)
	}
}

func TestClassifierResolvesGitCPathsFromActualCommandDirectory(t *testing.T) {
	workspace, repo := newGitFixture(t)
	writeFile(t, filepath.Join(repo, "file.txt"), "root\n")
	writeFile(t, filepath.Join(repo, "sub", "file.txt"), "nested\n")
	now := time.Date(2026, 9, 15, 4, 0, 0, 0, time.UTC)
	scope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses:   []string{"git_local_write"},
		Repositories:    []string{"workspace:repo"},
		WritePaths:      []string{"repo/file.txt"},
		RiskCeiling:     RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{Status: StatusActive, Scope: scope, ExpiresAt: now.Add(time.Hour)}

	for _, command := range []string{
		"git -C repo/sub add -- file.txt",
		"git -C repo -C sub add -- file.txt",
	} {
		action := ClassifyCommand(context.Background(), workspace, []string{command})
		if !action.Eligible {
			t.Fatalf("nested git -C command was not classified: %s => %+v", command, action)
		}
		assertContains(t, action.WritePaths, "repo/sub/file.txt")
		if stringSliceContains(action.WritePaths, "repo/file.txt") {
			t.Fatalf("nested git -C path was rebound to repository root: %s => %+v", command, action)
		}
		match := Match(grant, "issue 861 implementation", action, now)
		if match.Matched {
			t.Fatalf("root-only grant authorized nested git -C write: %s => %+v", command, match)
		}
		assertContains(t, match.Reasons, "write_path_out_of_scope:repo/sub/file.txt")
	}
}

func TestClassifierIncludesStagedTypeChanges(t *testing.T) {
	workspace, repo := newGitFixture(t)
	writeFile(t, filepath.Join(repo, "link-target.txt"), "docs/allowed.md")
	blob := gitOutput(t, repo, "hash-object", "-w", "--", "link-target.txt")
	runGit(t, repo, "update-index", "--cacheinfo", "120000,"+blob+",docs/allowed.md")

	action := ClassifyCommand(context.Background(), workspace, []string{"git -C repo commit -m type-change"})
	if !action.Eligible {
		t.Fatalf("staged type change was not classified: %+v", action)
	}
	assertContains(t, action.WritePaths, "repo/docs/allowed.md")

	now := time.Date(2026, 9, 15, 4, 30, 0, 0, time.UTC)
	scope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses:   []string{"git_local_write"},
		Repositories:    []string{"workspace:repo"},
		Targets:         []string{"branch:feat/issue-861"},
		WritePaths:      []string{"repo/other.txt"},
		RiskCeiling:     RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	match := Match(Grant{Status: StatusActive, Scope: scope, ExpiresAt: now.Add(time.Hour)}, "issue 861 implementation", action, now)
	if match.Matched {
		t.Fatalf("grant outside staged type-change path matched: %+v", match)
	}
	assertContains(t, match.Reasons, "write_path_out_of_scope:repo/docs/allowed.md")
}

func TestClassifierRejectsDeletedDirectoryGitAdd(t *testing.T) {
	workspace, repo := newGitFixture(t)
	if err := os.RemoveAll(filepath.Join(repo, "docs")); err != nil {
		t.Fatal(err)
	}
	action := ClassifyCommand(context.Background(), workspace, []string{"git -C repo add -- docs"})
	if action.Eligible {
		t.Fatalf("deleted directory git add became grant eligible: %+v", action)
	}
}

func TestClassifierRejectsCommitWhenUnstagedTrackedFileHasActiveFilter(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())

	writeFile(t, filepath.Join(repo, ".gitattributes"), "other.txt filter=reviewprobe\n")
	runGit(t, repo, "add", "--", ".gitattributes")
	runGit(t, repo, "commit", "-m", "record filter attributes without a configured command")
	runGit(t, repo, "config", "filter.reviewprobe.clean", "external-helper")
	writeFile(t, filepath.Join(repo, "docs", "allowed.md"), "allowed change\n")
	runGit(t, repo, "add", "--", "docs/allowed.md")
	writeFile(t, filepath.Join(repo, "other.txt"), "unstaged change that is outside the grant write domain\n")

	action := ClassifyCommand(ctx, workspace, []string{"git -C repo commit --dry-run -m ordinary"})
	if action.Eligible {
		t.Fatalf("commit with an active filter on an unstaged tracked file became grant eligible: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:git_commit_external_filter_not_supported")
}

func TestClassifierRejectsAutomaticCommitSigning(t *testing.T) {
	workspace, repo := newGitFixture(t)
	writeFile(t, filepath.Join(repo, "docs", "allowed.md"), "signed change\n")
	runGit(t, repo, "add", "--", "docs/allowed.md")
	runGit(t, repo, "config", "commit.gpgsign", "true")

	action := ClassifyCommand(context.Background(), workspace, []string{"git -C repo commit -m scoped"})
	if action.Eligible {
		t.Fatalf("automatic commit signing became grant eligible: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:git_commit_automatic_signing_not_supported")
}

func TestClassifierRejectsGitRemoteCommandOverrides(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := context.Background()

	for _, test := range []struct {
		name    string
		key     string
		command string
	}{
		{name: "push receivepack", key: "remote.origin.receivepack", command: "git -C repo push origin feat/issue-861"},
		{name: "fetch uploadpack", key: "remote.origin.uploadpack", command: "git -C repo fetch --no-tags --refmap= origin main"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runGit(t, repo, "config", test.key, "external-helper")
			t.Cleanup(func() { runGit(t, repo, "config", "--unset-all", test.key) })
			action := ClassifyCommand(ctx, workspace, []string{test.command})
			if action.Eligible {
				t.Fatalf("remote command override became grant eligible: %+v", action)
			}
		})
	}
}

func TestClassifierRejectsRemoteHelperProtocolAndVCSOverride(t *testing.T) {
	t.Run("unknown protocol helper", func(t *testing.T) {
		workspace, repo := newGitFixture(t)
		ctx := withGrantTestExecutables(t, context.Background())
		runGit(t, repo, "remote", "set-url", "origin", "reviewprobe://github.com/owner/repo")
		action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
		if action.Eligible {
			t.Fatalf("unknown Git remote helper protocol became grant eligible: %+v", action)
		}
		assertContains(t, action.Reasons, "segment_1:unresolved_git_remote:origin")
	})

	t.Run("remote vcs helper override", func(t *testing.T) {
		workspace, repo := newGitFixture(t)
		ctx := withGrantTestExecutables(t, context.Background())
		runGit(t, repo, "remote", "set-url", "origin", "https://github.com/owner/repo.git")
		runGit(t, repo, "config", "remote.origin.vcs", "reviewvcs")
		action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
		if action.Eligible {
			t.Fatalf("remote.<name>.vcs helper override became grant eligible: %+v", action)
		}
		assertContains(t, action.Reasons, "segment_1:unresolved_git_remote:origin")
	})
}

func TestClassifierRejectsAmbiguousGitRemoteTransportForms(t *testing.T) {
	for _, remoteURL := range []string{
		"reviewprobe::github.com/owner/repo",
		"example.com:path",
		"user@example.com:path",
	} {
		t.Run(remoteURL, func(t *testing.T) {
			workspace, repo := newGitFixture(t)
			ctx := withGrantTestExecutables(t, context.Background())
			runGit(t, repo, "remote", "set-url", "origin", remoteURL)

			marker := ""
			if strings.Contains(remoteURL, "::") {
				helperDir := t.TempDir()
				marker = filepath.Join(helperDir, "remote-helper-ran")
				if runtime.GOOS == "windows" {
					writeFile(t, filepath.Join(helperDir, "git-remote-reviewprobe.cmd"), "@echo off\r\n>\""+marker+"\" echo invoked\r\nexit /b 1\r\n")
				} else {
					helper := filepath.Join(helperDir, "git-remote-reviewprobe")
					writeFile(t, helper, "#!/bin/sh\nprintf invoked > '"+marker+"'\nexit 1\n")
					if err := os.Chmod(helper, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("PATH", helperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
				if runtime.GOOS != "windows" {
					// Reproduce the exact ambiguity from the review: a lookalike local
					// repository exists, while Git itself would still parse the same
					// string as a remote-helper transport.
					lookalike := filepath.Join(repo, filepath.FromSlash(remoteURL))
					if err := os.MkdirAll(filepath.Dir(lookalike), 0o755); err != nil {
						t.Fatal(err)
					}
					command := exec.Command("git", "init", "--bare", lookalike)
					if output, err := command.CombinedOutput(); err != nil {
						t.Fatalf("create remote-helper lookalike repository: %v\n%s", err, output)
					}
				}
			}

			for _, command := range []string{
				"git -C repo fetch --no-tags --refmap= origin main",
				"git -C repo push origin feat/issue-861",
			} {
				action := ClassifyCommand(ctx, workspace, []string{command})
				if action.Eligible {
					t.Fatalf("ambiguous Git remote transport became grant eligible: %s => %+v", remoteURL, action)
				}
				assertContains(t, action.Reasons, "segment_1:unresolved_git_remote:origin")
			}
			if marker != "" {
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("remote helper executed before ambiguous transport was rejected: %v", err)
				}
			}
		})
	}

	for _, path := range []string{`C:\repo`, "C:/repo"} {
		if hasAmbiguousGitScpSyntax(path) {
			t.Fatalf("Windows absolute drive path was misclassified as scp syntax: %q", path)
		}
	}
	if !hasAmbiguousGitScpSyntax("C:repo") {
		t.Fatal("Windows drive-relative path must remain fail-closed as ambiguous")
	}
}

func TestClassifierSanitizesGitChildPATH(t *testing.T) {
	workspace, _ := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())
	hostile := t.TempDir()
	t.Setenv("PATH", hostile+string(os.PathListSeparator)+os.Getenv("PATH"))

	action := ClassifyCommand(ctx, workspace, []string{"git -C repo status --short"})
	if !action.Eligible {
		t.Fatalf("ordinary status became ineligible while sanitizing child PATH: %+v", action)
	}
	pathValue, present := environmentValue(action.Environment, "PATH")
	if !present || strings.TrimSpace(pathValue) == "" {
		t.Fatalf("grant environment did not pin PATH: %+v", action.Environment)
	}
	for _, entry := range filepath.SplitList(pathValue) {
		if strings.EqualFold(filepath.Clean(entry), filepath.Clean(hostile)) {
			t.Fatalf("hostile PATH entry survived grant environment freezing: %q", pathValue)
		}
	}
}

func TestClassifierRejectsGitExecPathBeforeGitProbe(t *testing.T) {
	workspace, _ := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())
	fakeExecPath := t.TempDir()
	marker := filepath.Join(fakeExecPath, "child-helper-ran")
	if runtime.GOOS == "windows" {
		writeFile(t, filepath.Join(fakeExecPath, "git-upload-pack.cmd"), "@echo off\r\n>\""+marker+"\" echo invoked\r\nexit /b 1\r\n")
	} else {
		helper := filepath.Join(fakeExecPath, "git-upload-pack")
		writeFile(t, helper, "#!/bin/sh\nprintf invoked > '"+marker+"'\nexit 1\n")
		if err := os.Chmod(helper, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GIT_EXEC_PATH", fakeExecPath)

	action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
	if action.Eligible {
		t.Fatalf("non-empty GIT_EXEC_PATH became grant eligible: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:unsafe_grant_execution_environment:GIT_EXEC_PATH_not_supported")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Git child helper executed before grant classification failed closed: %v", err)
	}
}

func TestClassifierRejectsUntrustedCredentialHelperAcrossConfigScopes(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())
	runGit(t, repo, "remote", "set-url", "origin", "https://github.com/owner/repo.git")
	runGit(t, repo, "config", "credential.helper", "!external-helper")

	action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
	if action.Eligible {
		t.Fatalf("untrusted credential helper became grant eligible: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:unresolved_git_remote:origin")
}

func TestClassifierRejectsNetworkGitCommandOverrides(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := context.Background()
	runGit(t, repo, "remote", "set-url", "origin", "git@github.com:richarsun/mcpx.git")

	t.Run("environment override", func(t *testing.T) {
		t.Setenv("GIT_SSH_COMMAND", "external-helper")
		action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
		if action.Eligible {
			t.Fatalf("network Git environment override became grant eligible: %+v", action)
		}
	})

	t.Run("config override", func(t *testing.T) {
		runGit(t, repo, "config", "core.sshCommand", "external-helper")
		t.Cleanup(func() { runGit(t, repo, "config", "--unset-all", "core.sshCommand") })
		action := ClassifyCommand(ctx, workspace, []string{"git -C repo push origin feat/issue-861"})
		if action.Eligible {
			t.Fatalf("network Git config override became grant eligible: %+v", action)
		}
	})

	t.Run("repository credential helper", func(t *testing.T) {
		runGit(t, repo, "config", "credential.helper", "external-helper")
		t.Cleanup(func() { runGit(t, repo, "config", "--unset-all", "credential.helper") })
		action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
		if action.Eligible {
			t.Fatalf("repository-local credential helper became grant eligible: %+v", action)
		}
	})
}

func TestClassifierPinsFetchNoSubmoduleRecursion(t *testing.T) {
	workspace, _ := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())
	action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
	if !action.Eligible {
		t.Fatalf("ordinary bounded fetch was not grant eligible: %+v", action)
	}
	count := 0
	for _, argument := range action.Arguments {
		if argument == "--recurse-submodules=no" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("grant-backed fetch must pin exactly one --recurse-submodules=no in executed argv: %+v", action.Arguments)
	}
}

func TestClassifierRejectsHiddenInitializedSubmodule(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())
	child := filepath.Join(workspace, "child-source")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, child, "init")
	runGit(t, child, "config", "user.email", "submodule@example.invalid")
	runGit(t, child, "config", "user.name", "Submodule Fixture")
	writeFile(t, filepath.Join(child, "child.txt"), "child\n")
	runGit(t, child, "add", "--", "child.txt")
	runGit(t, child, "commit", "-m", "child fixture")
	runGit(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", child, "module")
	runGit(t, repo, "commit", "-m", "add initialized submodule")
	if err := os.Rename(filepath.Join(repo, ".gitmodules"), filepath.Join(repo, ".gitmodules.hidden")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repo, ".gitmodules")); !os.IsNotExist(err) {
		t.Fatalf("worktree .gitmodules should be absent for the regression fixture: %v", err)
	}
	runGit(t, repo, "config", "fetch.recurseSubmodules", "true")

	action := ClassifyCommand(ctx, workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
	if action.Eligible {
		t.Fatalf("fetch in repository with hidden initialized submodule became grant eligible: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:repository_outside_workspace_or_unsafe_automation")
}

func TestClassifierFetchRequiresEmptyRefmap(t *testing.T) {
	workspace, repo := newGitFixture(t)
	runGit(t, repo, "config", "--replace-all", "remote.origin.fetch", "+refs/heads/main:refs/heads/victim")

	unsafe := ClassifyCommand(context.Background(), workspace, []string{"git -C repo fetch --no-tags origin main"})
	if unsafe.Eligible {
		t.Fatalf("fetch using configured refmap became grant eligible: %+v", unsafe)
	}
	assertContains(t, unsafe.Reasons, "segment_1:git_fetch_requires_empty_--refmap=")

	safe := ClassifyCommand(context.Background(), workspace, []string{"git -C repo fetch --no-tags --refmap= origin main"})
	if !safe.Eligible {
		t.Fatalf("fetch with explicit empty refmap was not grant eligible: %+v", safe)
	}
	assertContains(t, safe.Targets, "remote:origin:main")
}

func TestClassifierRejectsImplicitPushConfiguration(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := context.Background()
	for _, test := range []struct {
		name  string
		key   string
		value string
	}{
		{name: "follow tags", key: "push.followTags", value: "true"},
		{name: "signed push", key: "push.gpgSign", value: "true"},
		{name: "push option", key: "push.pushOption", value: "ci.skip"},
		{name: "remote mirror", key: "remote.origin.mirror", value: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runGit(t, repo, "config", test.key, test.value)
			t.Cleanup(func() { runGit(t, repo, "config", "--unset-all", test.key) })
			action := ClassifyCommand(ctx, workspace, []string{"git -C repo push origin feat/issue-861"})
			if action.Eligible {
				t.Fatalf("implicit push configuration became grant eligible: %s=%s => %+v", test.key, test.value, action)
			}
		})
	}
}

func TestClassifierRequiresExplicitGitHubRepositoryAndTrustedHost(t *testing.T) {
	workspace, _ := newGitFixture(t)
	ctx := context.Background()
	for _, command := range []string{
		"gh pr create --base main --head feat/issue-861 --title issue-861 --body bounded-change",
		"gh pr view 861",
		"gh pr merge 861 --merge",
	} {
		action := ClassifyCommand(ctx, workspace, []string{command})
		if action.Eligible {
			t.Fatalf("implicit gh repository became grant eligible: %s => %+v", command, action)
		}
	}

	t.Setenv("GH_HOST", "ghe.example.com")
	action := ClassifyCommand(ctx, workspace, []string{"gh pr view 861 --repo richarsun/mcpx"})
	if action.Eligible {
		t.Fatalf("non-github.com GH_HOST became grant eligible: %+v", action)
	}
}

func TestClassifierIncludesBothSidesOfStagedRename(t *testing.T) {
	workspace, repo := newGitFixture(t)
	writeFile(t, filepath.Join(repo, "private", "a.txt"), "private\n")
	runGit(t, repo, "add", "--", "private/a.txt")
	runGit(t, repo, "commit", "-m", "add private file")
	runGit(t, repo, "mv", "private/a.txt", "docs/a.txt")

	action := ClassifyCommand(context.Background(), workspace, []string{"git -C repo commit -m rename"})
	if !action.Eligible {
		t.Fatalf("staged rename was not classified: %+v", action)
	}
	assertContains(t, action.WritePaths, "repo/private/a.txt")
	assertContains(t, action.WritePaths, "repo/docs/a.txt")

	now := time.Date(2026, 9, 15, 5, 0, 0, 0, time.UTC)
	scope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses:   []string{"git_local_write"},
		Repositories:    []string{"workspace:repo"},
		Targets:         []string{"branch:feat/issue-861"},
		WritePaths:      []string{"repo/docs/**"},
		RiskCeiling:     RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	match := Match(Grant{Status: StatusActive, Scope: scope, ExpiresAt: now.Add(time.Hour)}, "issue 861 implementation", action, now)
	if match.Matched {
		t.Fatalf("destination-only grant authorized rename source deletion: %+v", match)
	}
	assertContains(t, match.Reasons, "write_path_out_of_scope:repo/private/a.txt")
}

func TestClassifierRejectsOnlyActiveFilterCommands(t *testing.T) {
	workspace, repo := newGitFixture(t)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "filter.issue861.process")
	t.Setenv("GIT_CONFIG_VALUE_0", "external-helper")

	unused := ClassifyCommand(context.Background(), workspace, []string{"git -C repo status --short"})
	if !unused.Eligible {
		t.Fatalf("unused system/global filter definition blocked an ordinary repository: %+v", unused)
	}

	writeFile(t, filepath.Join(repo, ".gitattributes"), "docs/allowed.md filter=issue861\n")
	active := ClassifyCommand(context.Background(), workspace, []string{"git -C repo status --short"})
	if active.Eligible {
		t.Fatalf("active external filter command became grant eligible: %+v", active)
	}
}

func TestClassifierRejectsSwitchToBranchWithActiveFilter(t *testing.T) {
	workspace, repo := newGitFixture(t)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "filter.issue861.process")
	t.Setenv("GIT_CONFIG_VALUE_0", "external-helper")

	runGit(t, repo, "switch", "-c", "filtered-target")
	writeFile(t, filepath.Join(repo, ".gitattributes"), "docs/allowed.md filter=issue861\n")
	runGit(t, repo, "add", "--", ".gitattributes")
	runGit(t, repo, "commit", "-m", "activate target filter")
	runGit(t, repo, "switch", "feat/issue-861")

	action := ClassifyCommand(context.Background(), workspace, []string{"git -C repo switch filtered-target"})
	if action.Eligible {
		t.Fatalf("switch to target branch with active filter became grant eligible: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:git_switch_target_external_filter_not_supported")
}

func TestResolveGrantExecutableRejectsWorkspaceExternalPATHShadowBeforeProbe(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	marker := filepath.Join(outside, "shadow-executed.txt")
	name := "git"
	content := []byte("#!/bin/sh\nprintf shadow > '" + filepath.ToSlash(marker) + "'\nexit 0\n")
	if runtime.GOOS == "windows" {
		name = "git.cmd"
		content = []byte("@echo off\r\n> \"" + marker + "\" echo shadow\r\nexit /b 0\r\n")
	}
	shadow := filepath.Join(outside, name)
	if err := os.WriteFile(shadow, content, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", outside+string(os.PathListSeparator)+os.Getenv("PATH"))

	action := ClassifyCommand(context.Background(), workspace, []string{"git status --short"})
	if action.Eligible {
		t.Fatalf("workspace-external PATH shadow produced a grant-eligible action: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:cannot_resolve_trusted_executable:git")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("workspace-external PATH shadow executed during classification: %v", err)
	}
}

func TestGitReadTargetsRespectGrantAndNarrowing(t *testing.T) {
	workspace, repo := newGitFixture(t)
	ctx := withGrantTestExecutables(t, context.Background())
	commands := []string{
		"git -C repo log --oneline main",
		"git -C repo diff --no-ext-diff --no-textconv main",
		"git -C repo show --no-ext-diff --no-textconv --oneline --stat main",
	}
	for _, command := range commands {
		action := ClassifyCommand(ctx, workspace, []string{command})
		if !action.Eligible {
			t.Fatalf("explicit Git read target was not classifiable: %s => %+v", command, action)
		}
		assertContains(t, action.Targets, "branch:main")
	}

	runGit(t, repo, "switch", "main")
	currentBranchRead := ClassifyCommand(ctx, workspace, []string{"git -C repo branch --show-current"})
	if !currentBranchRead.Eligible {
		t.Fatalf("current branch read was not classifiable: %+v", currentBranchRead)
	}
	assertContains(t, currentBranchRead.Targets, "branch:main")
	plainBranchRead := ClassifyCommand(ctx, workspace, []string{"git -C repo branch"})
	if plainBranchRead.Eligible {
		t.Fatalf("plain git branch enumerates multiple refs and must not reuse a target-scoped grant: %+v", plainBranchRead)
	}
	assertContains(t, plainBranchRead.Reasons, "segment_1:plain_git_branch_read_not_grant_eligible")

	now := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	wideScope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses:   []string{"git_read"},
		Repositories:    []string{"workspace:repo"},
		Targets:         []string{"branch:main", "branch:feat/*"},
		RiskCeiling:     RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	narrowScope, err := NormalizeScope(Scope{
		PurposePatterns: []string{"issue 861*"},
		ActionClasses:   []string{"git_read"},
		Repositories:    []string{"workspace:repo"},
		Targets:         []string{"branch:feat/*"},
		RiskCeiling:     RiskOrdinary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := IsStrictSubset(narrowScope, wideScope); err != nil || !changed {
		t.Fatalf("expected target removal to be a valid narrow operation: changed=%v err=%v", changed, err)
	}
	mainRead := ClassifyCommand(ctx, workspace, []string{"git -C repo log --oneline main"})
	if match := Match(Grant{Status: StatusActive, Scope: wideScope, ExpiresAt: now.Add(time.Hour)}, "issue 861 implementation", mainRead, now); !match.Matched {
		t.Fatalf("main read should match before narrowing: %+v", match)
	}
	match := Match(Grant{Status: StatusActive, Scope: narrowScope, ExpiresAt: now.Add(time.Hour)}, "issue 861 implementation", mainRead, now)
	if match.Matched {
		t.Fatalf("read of removed branch target matched after narrowing: %+v", match)
	}
	assertContains(t, match.Reasons, "target_out_of_scope:branch:main")
	if match := Match(Grant{Status: StatusActive, Scope: wideScope, ExpiresAt: now.Add(time.Hour)}, "issue 861 implementation", currentBranchRead, now); !match.Matched {
		t.Fatalf("current main branch read should match before narrowing: %+v", match)
	}
	branchMatch := Match(Grant{Status: StatusActive, Scope: narrowScope, ExpiresAt: now.Add(time.Hour)}, "issue 861 implementation", currentBranchRead, now)
	if branchMatch.Matched {
		t.Fatalf("current main branch read matched after narrowing: %+v", branchMatch)
	}
	assertContains(t, branchMatch.Reasons, "target_out_of_scope:branch:main")

	head := gitOutput(t, repo, "rev-parse", "HEAD")
	runGit(t, repo, "checkout", "--detach", head)
	detached := ClassifyCommand(ctx, workspace, []string{"git -C repo branch --show-current"})
	if detached.Eligible {
		t.Fatalf("detached HEAD branch read became grant eligible: %+v", detached)
	}
	assertContains(t, detached.Reasons, "segment_1:cannot_resolve_git_branch_current_target")
}

func TestUnsafePathTextRejectsControlCharacters(t *testing.T) {
	for _, value := range []string{"docs/line\nbreak.md", "docs/tab\tname.md", "docs/nul\x00name.md", "docs/del\x7fname.md"} {
		if !hasUnsafePathText(value) {
			t.Fatalf("control-bearing path was accepted: %q", value)
		}
	}
	if hasUnsafePathText("docs/allowed name.md") {
		t.Fatal("ordinary path text was rejected")
	}
}

func TestClassifierRejectsRepositorySymlinkEscape(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	runGit(t, outside, "init")
	link := filepath.Join(workspace, "linked-repo")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation is unavailable on this host: %v", err)
	}
	action := ClassifyCommand(context.Background(), workspace, []string{"git -C linked-repo status --short"})
	if action.Eligible {
		t.Fatalf("repository symlink escaping Workspace became grant eligible: %+v", action)
	}
	assertContains(t, action.Reasons, "segment_1:git_-C_path_outside_workspace_or_not_directory")
}

func TestRepositoryGrantSafetyAcceptsOrdinaryFixture(t *testing.T) {
	workspace, repo := newGitFixture(t)
	if err := repositoryGrantSafety(context.Background(), workspace, repo); err != nil {
		t.Fatalf("ordinary fixture failed repository grant safety: %v", err)
	}
}

func withGrantTestExecutables(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gitExecutable, err = filepath.Abs(gitExecutable)
	if err != nil {
		t.Fatal(err)
	}
	return withGrantExecutableResolver(ctx, func(string) (string, error) {
		return gitExecutable, nil
	})
}

func newGitFixture(t *testing.T) (string, string) {
	t.Helper()
	workspace := t.TempDir()
	repo := filepath.Join(workspace, "repo")
	remote := filepath.Join(workspace, "remote.git")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "issue-861@example.invalid")
	runGit(t, repo, "config", "user.name", "Issue 861 Test")
	runGit(t, repo, "config", "commit.gpgsign", "false")
	runGit(t, repo, "config", "log.showSignature", "false")
	writeFile(t, filepath.Join(repo, "docs", "allowed.md"), "base\n")
	writeFile(t, filepath.Join(repo, "other.txt"), "base\n")
	runGit(t, repo, "add", "--", "docs/allowed.md", "other.txt")
	runGit(t, repo, "commit", "-m", "test fixture")
	runGit(t, repo, "branch", "-M", "main")
	runGit(t, repo, "switch", "-c", "feat/issue-861")

	command := exec.Command("git", "init", "--bare", remote)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, output)
	}
	runGit(t, repo, "remote", "add", "origin", remote)
	return workspace, repo
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"-C", repo}, args...)
	command := exec.Command("git", commandArgs...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func gitOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", repo}, args...)
	command := exec.Command("git", commandArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeFile(t *testing.T, filePath, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
