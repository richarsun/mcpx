package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
)

type pullRequestMetadata struct {
	BaseRefName string `json:"baseRefName"`
	HeadRefName string `json:"headRefName"`
}

type pullRequestMetadataResolver func(context.Context, string, string) (pullRequestMetadata, error)
type pullRequestMetadataResolverContextKey struct{}
type grantExecutableResolver func(string) (string, error)
type grantExecutableResolverContextKey struct{}
type grantExecutablePathsContextKey struct{}
type grantExecutionEnvironmentContextKey struct{}

func withPullRequestMetadataResolver(ctx context.Context, resolver pullRequestMetadataResolver) context.Context {
	return context.WithValue(ctx, pullRequestMetadataResolverContextKey{}, resolver)
}

func withGrantExecutableResolver(ctx context.Context, resolver grantExecutableResolver) context.Context {
	return context.WithValue(ctx, grantExecutableResolverContextKey{}, resolver)
}

func withGrantExecutablePath(ctx context.Context, name, executable string) context.Context {
	paths := map[string]string{}
	if current, ok := ctx.Value(grantExecutablePathsContextKey{}).(map[string]string); ok {
		for key, value := range current {
			paths[key] = value
		}
	}
	paths[name] = executable
	return context.WithValue(ctx, grantExecutablePathsContextKey{}, paths)
}

func grantExecutablePath(ctx context.Context, name string) string {
	if paths, ok := ctx.Value(grantExecutablePathsContextKey{}).(map[string]string); ok {
		if executable := strings.TrimSpace(paths[name]); executable != "" {
			return executable
		}
	}
	return name
}

func withGrantExecutionEnvironment(ctx context.Context, environment []string) context.Context {
	return context.WithValue(ctx, grantExecutionEnvironmentContextKey{}, append([]string(nil), environment...))
}

func grantExecutionEnvironment(ctx context.Context) []string {
	if environment, ok := ctx.Value(grantExecutionEnvironmentContextKey{}).([]string); ok {
		return append([]string(nil), environment...)
	}
	return append([]string(nil), os.Environ()...)
}

func frozenGrantExecutionEnvironment(executable, executablePath string) ([]string, error) {
	environment := append([]string(nil), os.Environ()...)
	if executable == "git" {
		if value, present := environmentValue(environment, "GIT_EXEC_PATH"); present && strings.TrimSpace(value) != "" {
			return nil, errors.New("GIT_EXEC_PATH_not_supported")
		}
		for _, entry := range environment {
			name, _, ok := strings.Cut(entry, "=")
			name = strings.TrimSpace(name)
			if ok && strings.HasPrefix(strings.ToUpper(name), "GIT_CONFIG_") {
				return nil, fmt.Errorf("%s_not_supported", name)
			}
		}
		// An explicitly empty GIT_EXEC_PATH still changes Git's child-program
		// lookup semantics on some platforms. Remove it completely and freeze
		// the resulting environment for both classification probes and execution.
		environment = environmentWithoutKeys(environment, "GIT_EXEC_PATH")
		childPath, err := trustedGitChildPath(executablePath)
		if err != nil {
			return nil, err
		}
		environment = setEnvironmentValue(environment, "PATH", childPath)
		environment = setEnvironmentValue(environment, "GIT_TERMINAL_PROMPT", "0")
		environment = setEnvironmentValue(environment, "GIT_PAGER", "")
	}
	if executable == "gh" {
		environment = setEnvironmentValue(environment, "GH_PROMPT_DISABLED", "1")
		environment = setEnvironmentValue(environment, "GH_PAGER", "")
	}
	return environment, nil
}

func trustedGitChildPath(executablePath string) (string, error) {
	if runtime.GOOS != "windows" {
		return strings.Join([]string{"/usr/bin", "/bin"}, string(os.PathListSeparator)), nil
	}
	root, err := trustedGitInstallationRoot(executablePath)
	if err != nil {
		return "", err
	}
	paths := []string{
		filepath.Join(root, "cmd"),
		filepath.Join(root, "mingw64", "bin"),
		filepath.Join(root, "usr", "bin"),
		filepath.Join(root, "mingw64", "libexec", "git-core"),
	}
	if systemRoot := strings.TrimSpace(os.Getenv("SystemRoot")); systemRoot != "" {
		paths = append(paths, filepath.Join(systemRoot, "System32"), systemRoot)
	}
	return strings.Join(paths, string(os.PathListSeparator)), nil
}

func trustedGitInstallationRoot(executablePath string) (string, error) {
	if runtime.GOOS != "windows" {
		clean := filepath.Clean(executablePath)
		if filepath.Dir(clean) != "/usr/bin" && filepath.Dir(clean) != "/bin" {
			return "", errors.New("trusted Git executable has no supported installation root")
		}
		return filepath.Dir(clean), nil
	}
	clean := filepath.Clean(executablePath)
	for _, environmentName := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		programFiles := strings.TrimSpace(os.Getenv(environmentName))
		if programFiles == "" {
			continue
		}
		root := filepath.Join(programFiles, "Git")
		for _, expected := range []string{
			filepath.Join(root, "cmd", "git.exe"),
			filepath.Join(root, "bin", "git.exe"),
			filepath.Join(root, "mingw64", "bin", "git.exe"),
		} {
			if strings.EqualFold(clean, filepath.Clean(expected)) {
				return root, nil
			}
		}
	}
	return "", errors.New("trusted Git executable has no supported installation root")
}

func environmentValue(environment []string, name string) (string, bool) {
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func environmentWithoutKeys(environment []string, names ...string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		remove := false
		if ok {
			for _, name := range names {
				if strings.EqualFold(key, name) {
					remove = true
					break
				}
			}
		}
		if !remove {
			result = append(result, entry)
		}
	}
	return result
}

func setEnvironmentValue(environment []string, name, value string) []string {
	result := environmentWithoutKeys(environment, name)
	return append(result, name+"="+value)
}

func mergeGrantEnvironment(base, overrides []string) []string {
	result := append([]string(nil), base...)
	for _, entry := range overrides {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		result = environmentWithoutKeys(result, key)
		result = append(result, entry)
	}
	return result
}

func resolveGrantExecutable(ctx context.Context, workspaceRoot, name string) (string, error) {
	if resolver, ok := ctx.Value(grantExecutableResolverContextKey{}).(grantExecutableResolver); ok && resolver != nil {
		executable, err := resolver(name)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(executable) == "" {
			return "", errors.New("trusted executable resolver returned an empty path")
		}
		return executable, nil
	}

	candidate, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("trusted executable path is not a regular file")
	}

	rootAbs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", err
	}
	if _, err := workspaceRelative(resolvedRoot, resolved); err == nil {
		return "", errors.New("trusted executable resolves inside the workspace")
	}
	if err := validateTrustedGrantExecutable(name, resolved, info); err != nil {
		return "", err
	}
	return resolved, nil
}

func validateTrustedGrantExecutable(name, resolved string, info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(filepath.Base(resolved), name+".exe") {
			return fmt.Errorf("trusted %s executable must resolve to %s.exe", name, name)
		}
		trusted := false
		for _, environmentName := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
			root := strings.TrimSpace(os.Getenv(environmentName))
			if root == "" {
				continue
			}
			var candidates []string
			switch name {
			case "git":
				candidates = []string{
					filepath.Join(root, "Git", "cmd", "git.exe"),
					filepath.Join(root, "Git", "bin", "git.exe"),
					filepath.Join(root, "Git", "mingw64", "bin", "git.exe"),
				}
			case "gh":
				candidates = []string{filepath.Join(root, "GitHub CLI", "gh.exe")}
			}
			for _, expected := range candidates {
				if strings.EqualFold(filepath.Clean(resolved), filepath.Clean(expected)) {
					trusted = true
					break
				}
			}
			if trusted {
				break
			}
		}
		if !trusted {
			return fmt.Errorf("trusted %s executable is not in a supported system installation path", name)
		}
	} else {
		if info.Mode().Perm()&0o111 == 0 {
			return errors.New("trusted executable path is not executable")
		}
		directory := filepath.Clean(filepath.Dir(resolved))
		if directory != "/usr/bin" && directory != "/bin" {
			return fmt.Errorf("trusted %s executable is not in a supported system installation path", name)
		}
	}

	trustedBinary, err := executableHasTrustedBinaryFormat(resolved)
	if err != nil {
		return err
	}
	if !trustedBinary {
		return fmt.Errorf("trusted %s executable has an unsupported binary format", name)
	}
	return nil
}

func executableHasTrustedBinaryFormat(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	header := make([]byte, 4)
	count, err := file.Read(header)
	if err != nil && count == 0 {
		return false, err
	}
	if runtime.GOOS == "windows" {
		return count >= 2 && header[0] == 'M' && header[1] == 'Z', nil
	}
	if count < 4 {
		return false, nil
	}
	magic := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	switch magic {
	case 0x7f454c46, // ELF
		0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, // Mach-O
		0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca: // universal Mach-O
		return true, nil
	default:
		return false, nil
	}
}

// ClassifyCommand converts already policy-split shell segments into the exact
// dimensions matched by a grant. Any unsupported syntax or segment makes the
// whole command ineligible; callers then fall back to normal confirmation.
func ClassifyCommand(ctx context.Context, workspaceRoot string, segments []string) Action {
	combined := Action{Eligible: true, Risk: RiskOrdinary}
	if strings.TrimSpace(workspaceRoot) == "" || len(segments) == 0 {
		return ineligible("missing_workspace_or_command")
	}
	if len(segments) != 1 {
		return ineligible("compound_commands_not_grant_eligible")
	}
	for index, segment := range segments {
		action := classifySegment(ctx, workspaceRoot, segment)
		combined.Classes = append(combined.Classes, action.Classes...)
		combined.Repositories = append(combined.Repositories, action.Repositories...)
		combined.Targets = append(combined.Targets, action.Targets...)
		combined.WritePaths = append(combined.WritePaths, action.WritePaths...)
		combined.Executable = action.Executable
		combined.Arguments = append([]string(nil), action.Arguments...)
		combined.Environment = append([]string(nil), action.Environment...)
		if action.Summary != "" {
			if combined.Summary != "" {
				combined.Summary += "; "
			}
			combined.Summary += action.Summary
		}
		if !action.Eligible {
			combined.Eligible = false
			for _, reason := range action.Reasons {
				combined.Reasons = append(combined.Reasons, fmt.Sprintf("segment_%d:%s", index+1, reason))
			}
		}
		if action.Risk != "" && action.Risk != RiskOrdinary {
			combined.Risk = action.Risk
		}
	}
	combined.Classes = sortedUnique(combined.Classes)
	combined.Repositories = sortedUnique(combined.Repositories)
	combined.Targets = sortedUnique(combined.Targets)
	combined.WritePaths = sortedUniqueExact(combined.WritePaths)
	combined.Reasons = sortedUnique(combined.Reasons)
	if len(combined.Classes) == 0 {
		combined.Eligible = false
		combined.Reasons = append(combined.Reasons, "no_supported_action_class")
	}
	if combined.Eligible {
		if len(combined.Repositories) == 0 {
			combined.Eligible = false
			combined.Reasons = append(combined.Reasons, "grant_eligible_action_requires_repository")
		}
		if stringSliceContains(combined.Classes, "git_read") && len(combined.Targets) == 0 {
			combined.Eligible = false
			combined.Reasons = append(combined.Reasons, "grant_eligible_git_read_requires_target")
		}
	}
	return combined
}

func classifySegment(ctx context.Context, workspaceRoot, raw string) Action {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ineligible("empty_segment")
	}
	if containsUnsupportedShellSyntax(raw) {
		return ineligible("unsupported_shell_syntax")
	}
	words, err := shellWords(raw)
	if err != nil || len(words) == 0 {
		return ineligible("unparseable_command")
	}
	if riskReason := obviousHighRisk(words); riskReason != "" {
		return Action{Eligible: false, Risk: "high", Reasons: []string{riskReason}}
	}
	executable, trusted := trustedGrantExecutable(words[0])
	if !trusted {
		return ineligible("untrusted_executable_token")
	}
	if executable == "go" {
		return ineligible("verification_commands_execute_repository_code")
	}
	executablePath, err := resolveGrantExecutable(ctx, workspaceRoot, executable)
	if err != nil {
		return ineligible("cannot_resolve_trusted_executable:" + executable)
	}
	executionEnvironment, err := frozenGrantExecutionEnvironment(executable, executablePath)
	if err != nil {
		return ineligible("unsafe_grant_execution_environment:" + err.Error())
	}
	ctx = withGrantExecutablePath(ctx, executable, executablePath)
	ctx = withGrantExecutionEnvironment(ctx, executionEnvironment)
	var action Action
	switch executable {
	case "git":
		action = classifyGit(ctx, workspaceRoot, words[1:])
	case "gh":
		action = classifyGitHub(ctx, workspaceRoot, words[1:])
	default:
		return ineligible("unsupported_executable:" + executable)
	}
	if action.Eligible {
		action.Executable = executablePath
		arguments := append([]string(nil), words[1:]...)
		if action.Arguments != nil {
			arguments = append([]string(nil), action.Arguments...)
		}
		if executable == "git" && action.Summary == "git fetch" {
			arguments, err = pinGitFetchNoRecurse(arguments)
			if err != nil {
				return ineligible("cannot_pin_git_fetch_no_submodule_recursion")
			}
		}
		action.Arguments = arguments
		action.Environment = append([]string(nil), executionEnvironment...)
	}
	return action
}

func pinGitFetchNoRecurse(args []string) ([]string, error) {
	for index := 0; index < len(args); {
		switch args[index] {
		case "-C":
			if index+1 >= len(args) {
				return nil, errors.New("git -C requires path")
			}
			index += 2
		case "--no-pager", "--literal-pathspecs":
			index++
		default:
			if !strings.EqualFold(args[index], "fetch") {
				return nil, errors.New("git fetch subcommand not found")
			}
			for _, arg := range args[index+1:] {
				if arg == "--recurse-submodules=no" {
					return append([]string(nil), args...), nil
				}
			}
			result := make([]string, 0, len(args)+1)
			result = append(result, args[:index+1]...)
			result = append(result, "--recurse-submodules=no")
			result = append(result, args[index+1:]...)
			return result, nil
		}
	}
	return nil, errors.New("git fetch subcommand not found")
}

func classifyGit(ctx context.Context, workspaceRoot string, args []string) Action {
	commandDir, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return ineligible("cannot_resolve_workspace_directory")
	}
	prefix := make([]string, 0, 4)
	for len(args) > 0 {
		switch args[0] {
		case "-C":
			if len(args) < 2 {
				return ineligible("git_-C_requires_path")
			}
			commandDir, err = resolveGitCommandDirectory(workspaceRoot, commandDir, args[1])
			if err != nil {
				return ineligible("git_-C_path_outside_workspace_or_not_directory")
			}
			prefix = append(prefix, args[0], args[1])
			args = args[2:]
		case "--no-pager", "--literal-pathspecs":
			prefix = append(prefix, args[0])
			args = args[1:]
		case "-c", "--git-dir", "--work-tree", "--namespace":
			return ineligible("git_global_override_not_supported")
		default:
			goto parsedGlobals
		}
	}
parsedGlobals:
	if len(args) == 0 {
		return ineligible("git_subcommand_required")
	}
	repo, repoAbs, err := workspaceGitRepository(ctx, workspaceRoot, commandDir)
	if err != nil {
		return ineligible("repository_outside_workspace_or_unsafe_automation")
	}
	subcommand := strings.ToLower(args[0])
	subargs := args[1:]
	var action Action
	switch subcommand {
	case "status", "diff", "log", "show", "rev-parse":
		action = classifyGitRead(ctx, repo, repoAbs, subcommand, subargs)
	case "branch":
		action = classifyGitBranch(ctx, repo, repoAbs, subargs)
	case "fetch":
		action = classifyGitFetch(ctx, workspaceRoot, repo, repoAbs, subargs)
	case "switch":
		action = classifyGitSwitch(ctx, workspaceRoot, repo, repoAbs, subargs)
	case "add":
		action = classifyGitAdd(ctx, workspaceRoot, repo, repoAbs, commandDir, subargs)
	case "commit":
		action = classifyGitCommit(ctx, workspaceRoot, repo, repoAbs, subargs)
	case "push":
		action = classifyGitPush(ctx, workspaceRoot, repo, repoAbs, subargs)
	default:
		return ineligible("unsupported_git_subcommand:" + subcommand)
	}
	if action.Eligible && action.Arguments != nil {
		arguments := make([]string, 0, len(prefix)+1+len(action.Arguments))
		arguments = append(arguments, prefix...)
		arguments = append(arguments, subcommand)
		arguments = append(arguments, action.Arguments...)
		action.Arguments = arguments
	}
	return action
}

func classifyGitRead(ctx context.Context, repo, repoAbs, subcommand string, args []string) Action {
	switch subcommand {
	case "diff":
		return classifyGitDiffRead(ctx, repo, repoAbs, args)
	case "show":
		return classifyGitShowRead(ctx, repo, repoAbs, args)
	case "log":
		return classifyGitLogRead(ctx, repo, repoAbs, args)
	case "rev-parse":
		return classifyGitRevParseRead(ctx, repo, repoAbs, args)
	case "status":
		for _, arg := range args {
			lower := strings.ToLower(strings.TrimSpace(arg))
			if lower == "--ext-diff" || strings.HasPrefix(lower, "--ext-diff=") ||
				lower == "--textconv" || strings.HasPrefix(lower, "--textconv=") ||
				lower == "--no-index" || lower == "--output" || strings.HasPrefix(lower, "--output=") {
				return ineligible("git_read_external_or_output_option:" + arg)
			}
			normalized := strings.ReplaceAll(arg, "\\", "/")
			if filepath.IsAbs(arg) || len(normalized) >= 2 && normalized[1] == ':' ||
				normalized == ".." || strings.HasPrefix(normalized, "../") || strings.Contains(normalized, "/../") {
				return ineligible("git_read_path_outside_repository:" + arg)
			}
		}
		usesExternalAttributes, err := repositoryUsesExternalAttributes(ctx, repoAbs, "")
		if err != nil {
			return ineligible("cannot_resolve_active_git_attributes")
		}
		if usesExternalAttributes {
			return ineligible("git_status_external_filter_not_supported")
		}
		target, _, err := resolveGitReadTarget(ctx, repoAbs, "")
		if err != nil {
			return ineligible("cannot_resolve_git_status_target")
		}
		return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_read"}, Repositories: []string{repo}, Targets: []string{target}, Summary: "git status", Arguments: canonicalGitReadArguments(args, -1, "")}
	default:
		return ineligible("unsupported_git_read_subcommand:" + subcommand)
	}
}

func classifyGitLogRead(ctx context.Context, repo, repoAbs string, args []string) Action {
	showSignatures, err := gitReadSignaturesEnabled(ctx, repoAbs)
	if err != nil {
		return ineligible("cannot_resolve_git_log_signature_configuration")
	}
	if showSignatures {
		return ineligible("git_log_signature_verification_not_supported")
	}
	hasOneline := false
	revision := ""
	revisionIndex := -1
	for index, arg := range args {
		switch {
		case arg == "--oneline":
			if hasOneline {
				return ineligible("duplicate_git_log_option:--oneline")
			}
			hasOneline = true
		case isShortNumericGitLogLimit(arg):
			continue
		case !strings.HasPrefix(arg, "-") && safeGitReadToken(arg):
			if revision != "" {
				return ineligible("multiple_git_log_revisions_not_supported")
			}
			revision = arg
			revisionIndex = index
		default:
			return ineligible("unsupported_git_log_option_or_path:" + arg)
		}
	}
	if !hasOneline {
		return ineligible("git_log_requires_explicit_--oneline")
	}
	target, canonicalRevision, err := resolveGitReadTarget(ctx, repoAbs, revision)
	if err != nil {
		return ineligible("cannot_resolve_git_log_target")
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_read"}, Repositories: []string{repo}, Targets: []string{target}, Summary: "git log", Arguments: canonicalGitReadArguments(args, revisionIndex, canonicalRevision)}
}

func classifyGitRevParseRead(ctx context.Context, repo, repoAbs string, args []string) Action {
	revision := ""
	revisionIndex := -1
	for index, arg := range args {
		switch arg {
		case "--show-toplevel", "--show-prefix", "--show-cdup", "--show-superproject-working-tree", "--is-inside-work-tree", "--is-bare-repository", "--absolute-git-dir", "--git-dir", "--git-common-dir":
			continue
		default:
			if strings.HasPrefix(arg, "-") || revision != "" || !safeGitReadToken(arg) {
				return ineligible("unsupported_git_rev_parse_argument:" + arg)
			}
			revision = arg
			revisionIndex = index
		}
	}
	target, canonicalRevision, err := resolveGitReadTarget(ctx, repoAbs, revision)
	if err != nil {
		return ineligible("cannot_resolve_git_rev_parse_target")
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_read"}, Repositories: []string{repo}, Targets: []string{target}, Summary: "git rev-parse", Arguments: canonicalGitReadArguments(args, revisionIndex, canonicalRevision)}
}

func classifyGitDiffRead(ctx context.Context, repo, repoAbs string, args []string) Action {
	hasNoExternalDiff := false
	hasNoTextconv := false
	separator := false
	pathCount := 0
	revision := ""
	revisionIndex := -1
	seenOptions := map[string]bool{}
	for index, arg := range args {
		if separator {
			if !safeGitReadToken(arg) {
				return ineligible("unsupported_git_diff_path:" + arg)
			}
			pathCount++
			continue
		}
		switch arg {
		case "--":
			separator = true
		case "--no-ext-diff":
			if seenOptions[arg] {
				return ineligible("duplicate_git_diff_option:" + arg)
			}
			seenOptions[arg] = true
			hasNoExternalDiff = true
		case "--no-textconv":
			if seenOptions[arg] {
				return ineligible("duplicate_git_diff_option:" + arg)
			}
			seenOptions[arg] = true
			hasNoTextconv = true
		case "--stat", "--summary", "--check", "--name-only", "--name-status", "--cached", "--staged", "--quiet", "--exit-code":
			if seenOptions[arg] {
				return ineligible("duplicate_git_diff_option:" + arg)
			}
			seenOptions[arg] = true
		default:
			if strings.HasPrefix(arg, "-") {
				return ineligible("unsupported_git_diff_option:" + arg)
			}
			if revision != "" || !safeGitReadToken(arg) {
				return ineligible("unsupported_git_diff_revision_or_path:" + arg)
			}
			revision = arg
			revisionIndex = index
		}
	}
	if separator && pathCount == 0 {
		return ineligible("git_diff_path_required_after_separator")
	}
	if !hasNoExternalDiff || !hasNoTextconv {
		return ineligible("git_diff_requires_--no-ext-diff_and_--no-textconv")
	}
	usesExternalAttributes, err := repositoryUsesExternalAttributes(ctx, repoAbs, "")
	if err != nil {
		return ineligible("cannot_resolve_active_git_attributes")
	}
	if usesExternalAttributes {
		return ineligible("git_diff_external_filter_not_supported")
	}
	currentTarget, _, err := resolveGitReadTarget(ctx, repoAbs, "")
	if err != nil {
		return ineligible("cannot_resolve_git_diff_current_target")
	}
	targets := []string{currentTarget}
	canonicalRevision := ""
	if revision != "" {
		revisionTarget, canonical, targetErr := resolveGitReadTarget(ctx, repoAbs, revision)
		if targetErr != nil {
			return ineligible("cannot_resolve_git_diff_revision_target")
		}
		targets = append(targets, revisionTarget)
		canonicalRevision = canonical
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_read"}, Repositories: []string{repo}, Targets: sortedUnique(targets), Summary: "git diff", Arguments: canonicalGitReadArguments(args, revisionIndex, canonicalRevision)}
}

func classifyGitShowRead(ctx context.Context, repo, repoAbs string, args []string) Action {
	hasNoExternalDiff := false
	hasNoTextconv := false
	hasOneline := false
	object := ""
	objectIndex := -1
	seenOptions := map[string]bool{}
	for index, arg := range args {
		switch arg {
		case "--no-ext-diff":
			if seenOptions[arg] {
				return ineligible("duplicate_git_show_option:" + arg)
			}
			seenOptions[arg] = true
			hasNoExternalDiff = true
		case "--no-textconv":
			if seenOptions[arg] {
				return ineligible("duplicate_git_show_option:" + arg)
			}
			seenOptions[arg] = true
			hasNoTextconv = true
		case "--oneline":
			if seenOptions[arg] {
				return ineligible("duplicate_git_show_option:" + arg)
			}
			seenOptions[arg] = true
			hasOneline = true
		case "--stat", "--summary", "--name-only", "--name-status", "--no-patch", "-s":
			if seenOptions[arg] {
				return ineligible("duplicate_git_show_option:" + arg)
			}
			seenOptions[arg] = true
		default:
			if strings.HasPrefix(arg, "-") {
				return ineligible("unsupported_git_show_option:" + arg)
			}
			if object != "" || !safeGitReadToken(arg) {
				return ineligible("unsupported_git_show_object_or_path:" + arg)
			}
			object = arg
			objectIndex = index
		}
	}
	if !hasNoExternalDiff || !hasNoTextconv {
		return ineligible("git_show_requires_--no-ext-diff_and_--no-textconv")
	}
	if !hasOneline {
		return ineligible("git_show_requires_explicit_--oneline")
	}
	if object == "" {
		return ineligible("git_show_requires_explicit_object")
	}
	target, canonicalObject, err := resolveGitReadTarget(ctx, repoAbs, object)
	if err != nil {
		return ineligible("cannot_resolve_git_show_target")
	}
	showSignatures, err := gitReadSignaturesEnabled(ctx, repoAbs)
	if err != nil {
		return ineligible("cannot_resolve_git_show_signature_configuration")
	}
	if showSignatures {
		return ineligible("git_show_signature_verification_not_supported")
	}
	usesExternalAttributes, err := repositoryUsesExternalAttributes(ctx, repoAbs, canonicalObject)
	if err != nil {
		return ineligible("cannot_resolve_git_show_attributes")
	}
	if usesExternalAttributes {
		return ineligible("git_show_external_filter_not_supported")
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_read"}, Repositories: []string{repo}, Targets: []string{target}, Summary: "git show", Arguments: canonicalGitReadArguments(args, objectIndex, canonicalObject)}
}

func gitReadSignaturesEnabled(ctx context.Context, repoAbs string) (bool, error) {
	value, err := boundedGitOptional(ctx, repoAbs, "config", "--bool", "--get", "log.showSignature")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errors.New("invalid log.showSignature value")
	}
}

func safeGitReadToken(value string) bool {
	if !safeGitName(value) {
		return false
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	if filepath.IsAbs(value) || strings.HasPrefix(normalized, "/") || len(normalized) >= 2 && normalized[1] == ':' {
		return false
	}
	return normalized != ".." && !strings.HasPrefix(normalized, "../") && !strings.Contains(normalized, "/../")
}

func canonicalGitReadArguments(args []string, revisionIndex int, canonicalRevision string) []string {
	result := make([]string, len(args))
	copy(result, args)
	if revisionIndex >= 0 && canonicalRevision != "" {
		result[revisionIndex] = canonicalRevision
	}
	return result
}

func classifyGitBranch(ctx context.Context, repo, repoAbs string, args []string) Action {
	if len(args) == 0 {
		return ineligible("plain_git_branch_read_not_grant_eligible")
	}
	if len(args) == 1 && args[0] == "--show-current" {
		target, _, err := resolveGitReadTarget(ctx, repoAbs, "")
		if err != nil {
			return ineligible("cannot_resolve_git_branch_current_target")
		}
		return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_read"}, Repositories: []string{repo}, Targets: []string{target}, Summary: "git branch --show-current", Arguments: canonicalGitReadArguments(args, -1, "")}
	}
	deleteMode := false
	branches := make([]string, 0)
	for _, arg := range args {
		switch arg {
		case "-d", "--delete":
			if deleteMode {
				return ineligible("duplicate_git_branch_delete_option")
			}
			deleteMode = true
		case "-D", "--force", "-f", "--move", "-m", "-M", "--copy", "-c", "-C", "--edit-description", "--set-upstream-to", "--unset-upstream", "--create-reflog":
			return highRisk("unsafe_git_branch_mutation")
		default:
			if strings.HasPrefix(arg, "-") {
				return ineligible("unsupported_git_branch_option:" + arg)
			}
			branches = append(branches, arg)
		}
	}
	if !deleteMode || len(branches) == 0 {
		return ineligible("only_no_arg_or_show_current_read_and_safe_delete_are_supported")
	}
	current, _ := currentGitBranch(ctx, repoAbs)
	targets := make([]string, 0, len(branches))
	for _, branch := range branches {
		if branch == current || !safeGitName(branch) {
			return highRisk("cannot_delete_current_or_unsafe_branch")
		}
		targets = append(targets, "branch:"+branch)
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_cleanup"}, Repositories: []string{repo}, Targets: targets, Summary: "git branch -d"}
}

func classifyGitFetch(ctx context.Context, workspaceRoot, repo, repoAbs string, args []string) Action {
	positionals := make([]string, 0)
	noTags := false
	emptyRefmap := false
	for _, arg := range args {
		switch arg {
		case "--no-tags":
			noTags = true
			continue
		case "--refmap=":
			emptyRefmap = true
			continue
		case "--quiet", "-q", "--verbose", "-v", "--progress", "--no-progress", "--no-write-fetch-head", "--recurse-submodules=no":
			continue
		case "--all", "--multiple", "--prune", "--prune-tags", "--tags", "--force", "-f", "--update-head-ok":
			return ineligible("broad_or_mutating_git_fetch_option:" + arg)
		default:
			if strings.HasPrefix(arg, "-") {
				return ineligible("unsupported_git_fetch_option:" + arg)
			}
			positionals = append(positionals, arg)
		}
	}
	if len(positionals) < 2 {
		return ineligible("explicit_git_fetch_remote_and_ref_required")
	}
	if !noTags {
		return ineligible("git_fetch_requires_--no-tags")
	}
	if !emptyRefmap {
		return ineligible("git_fetch_requires_empty_--refmap=")
	}
	remote := positionals[0]
	refs := positionals[1:]
	if !safeGitName(remote) {
		return ineligible("unsafe_git_remote")
	}
	remoteRepo, err := resolveGitRemote(ctx, workspaceRoot, repoAbs, remote, false)
	if err != nil {
		return ineligible("unresolved_git_remote:" + remote)
	}
	targets := make([]string, 0, len(refs))
	for _, ref := range refs {
		if strings.EqualFold(ref, "tag") {
			return ineligible("git_fetch_tag_shorthand_not_supported")
		}
		if strings.ContainsAny(ref, "+:*?[") || !safeGitName(ref) {
			return highRisk("unsafe_git_fetch_refspec")
		}
		targets = append(targets, "remote:"+remote+":"+ref)
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_remote_read"}, Repositories: []string{repo, remoteRepo}, Targets: targets, Summary: "git fetch"}
}

func classifyGitSwitch(ctx context.Context, workspaceRoot, repo, repoAbs string, args []string) Action {
	branch := ""
	create := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-c", "--create":
			if index+1 >= len(args) {
				return ineligible("git_switch_create_requires_branch")
			}
			if create || branch != "" {
				return ineligible("git_switch_create_start_point_not_supported")
			}
			create = true
			branch = args[index+1]
			index++
		case "-C", "--force-create", "-f", "--force", "--discard-changes", "--detach", "--orphan", "-m", "--merge":
			return highRisk("unsafe_git_switch_option:" + arg)
		default:
			if strings.HasPrefix(arg, "-") {
				return ineligible("unsupported_git_switch_option:" + arg)
			}
			if branch != "" {
				return ineligible("multiple_git_switch_targets")
			}
			branch = arg
		}
	}
	if branch == "" || !safeGitName(branch) {
		return ineligible("safe_git_switch_branch_required")
	}
	summary := "git switch"
	writePaths := []string(nil)
	if create {
		summary = "git switch -c"
	} else {
		usesExternalAttributes, err := repositoryUsesExternalAttributes(ctx, repoAbs, branch)
		if err != nil {
			return ineligible("cannot_resolve_git_switch_target_attributes")
		}
		if usesExternalAttributes {
			return ineligible("git_switch_target_external_filter_not_supported")
		}
		// Switching to an existing branch may replace any tracked worktree file.
		// Model that full side-effect domain so a narrow file grant cannot
		// silently authorize a whole-worktree transition.
		worktree, err := commandWritePath(workspaceRoot, repoAbs, ".")
		if err != nil {
			return ineligible("cannot_resolve_git_switch_write_domain")
		}
		writePaths = []string{worktree}
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_local_write"}, Repositories: []string{repo}, Targets: []string{"branch:" + branch}, WritePaths: writePaths, Summary: summary}
}

func classifyGitAdd(ctx context.Context, workspaceRoot, repo, repoAbs, commandDir string, args []string) Action {
	paths := make([]string, 0)
	separator := false
	for _, arg := range args {
		if arg == "--" {
			separator = true
			continue
		}
		if !separator && strings.HasPrefix(arg, "-") {
			switch arg {
			case "-A", "--all", "-u", "--update", "--renormalize", "-N", "--intent-to-add", "-p", "--patch":
				return ineligible("broad_or_interactive_git_add_option:" + arg)
			default:
				return ineligible("unsupported_git_add_option:" + arg)
			}
		}
		if strings.HasPrefix(arg, ":") {
			return ineligible("git_add_pathspec_magic_not_supported")
		}
		if strings.ContainsAny(arg, "*?[") {
			return ineligible("git_add_glob_not_supported")
		}
		if hasUnsafePathText(arg) {
			return ineligible("git_add_control_character_not_supported")
		}
		attributePath, err := literalGitAddPath(ctx, repoAbs, commandDir, arg)
		if err != nil {
			return ineligible("git_add_requires_single_literal_file_path")
		}
		normalized, err := commandWritePath(workspaceRoot, repoAbs, attributePath)
		if err != nil {
			return ineligible("git_add_path_outside_workspace")
		}
		if hasGitAttribute(ctx, repoAbs, "filter", attributePath) {
			return ineligible("git_add_external_filter_not_supported:" + normalized)
		}
		paths = append(paths, normalized)
	}
	if len(paths) == 0 {
		return ineligible("git_add_path_required")
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_local_write"}, Repositories: []string{repo}, WritePaths: paths, Summary: "git add"}
}

func classifyGitCommit(ctx context.Context, workspaceRoot, repo, repoAbs string, args []string) Action {
	messageProvided := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "--amend", "-a", "--all", "--allow-empty", "--allow-empty-message", "--fixup", "--squash", "--no-verify", "-n", "--reset-author", "-S", "--gpg-sign", "-i", "--include", "-o", "--only", "--pathspec-from-file", "--pathspec-file-nul":
			return highRisk("unsafe_or_broad_git_commit_option:" + arg)
		case "--trailer":
			return ineligible("git_commit_trailer_not_supported")
		case "-m", "--message", "--author", "--date", "--cleanup":
			if index+1 >= len(args) {
				return ineligible("git_commit_option_requires_value:" + arg)
			}
			if arg == "-m" || arg == "--message" {
				messageProvided = true
			}
			index++
		case "-v", "--verbose":
			return ineligible("git_commit_verbose_not_supported")
		case "-q", "--quiet", "-s", "--signoff", "--dry-run", "--status", "--no-status":
			continue
		default:
			if (strings.HasPrefix(arg, "-m") && len(arg) > 2) || strings.HasPrefix(arg, "--message=") {
				messageProvided = true
				continue
			}
			if strings.HasPrefix(arg, "--trailer=") {
				return ineligible("git_commit_trailer_not_supported")
			}
			if strings.HasPrefix(arg, "--author=") || strings.HasPrefix(arg, "--date=") || strings.HasPrefix(arg, "--cleanup=") {
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return ineligible("unsupported_git_commit_option:" + arg)
			}
			return ineligible("git_commit_pathspec_not_supported:" + arg)
		}
	}
	if !messageProvided {
		return ineligible("git_commit_requires_explicit_message")
	}
	configuredSigning, err := boundedGitOptional(ctx, repoAbs, "config", "--bool", "--get", "commit.gpgSign")
	if err != nil {
		return ineligible("cannot_resolve_git_commit_signing_config")
	}
	if strings.EqualFold(strings.TrimSpace(configuredSigning), "true") {
		return ineligible("git_commit_automatic_signing_not_supported")
	}
	usesExternalAttributes, err := repositoryUsesExternalAttributes(ctx, repoAbs, "")
	if err != nil {
		return ineligible("cannot_resolve_git_commit_attributes")
	}
	if usesExternalAttributes {
		return ineligible("git_commit_external_filter_not_supported")
	}
	branch, err := currentGitBranch(ctx, repoAbs)
	if err != nil || branch == "HEAD" || !safeGitName(branch) {
		return ineligible("attached_git_branch_required")
	}
	staged, err := stagedGitPaths(ctx, workspaceRoot, repoAbs)
	if err != nil {
		return ineligible("cannot_resolve_staged_write_paths")
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_local_write"}, Repositories: []string{repo}, Targets: []string{"branch:" + branch}, WritePaths: staged, Summary: "git commit"}
}

func classifyGitPush(ctx context.Context, workspaceRoot, repo, repoAbs string, args []string) Action {
	positionals := make([]string, 0)
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if lower == "-f" || strings.HasPrefix(lower, "--force") || lower == "--delete" || lower == "-d" || lower == "--mirror" || lower == "--all" || lower == "--tags" || lower == "--prune" || strings.HasPrefix(arg, ":") {
			return highRisk("force_or_delete_git_push")
		}
		if strings.HasPrefix(arg, "-") {
			switch arg {
			case "--porcelain", "--dry-run", "-n":
				continue
			case "-u", "--set-upstream", "--no-verify":
				return ineligible("git_push_local_config_or_hook_bypass_not_supported:" + arg)
			default:
				return ineligible("unsupported_git_push_option:" + arg)
			}
		}
		positionals = append(positionals, arg)
	}
	if len(positionals) == 0 {
		return ineligible("explicit_git_push_remote_required")
	}
	remote := positionals[0]
	if !safeGitName(remote) {
		return ineligible("unsafe_git_remote")
	}
	remoteRepo, err := resolveGitRemote(ctx, workspaceRoot, repoAbs, remote, true)
	if err != nil {
		return ineligible("unresolved_git_remote:" + remote)
	}
	followTags, err := boundedGitOptional(ctx, repoAbs, "config", "--bool", "--get", "push.followTags")
	if err != nil {
		return ineligible("cannot_resolve_push_follow_tags_config")
	}
	if strings.EqualFold(strings.TrimSpace(followTags), "true") {
		return ineligible("git_push_follow_tags_config_not_supported")
	}
	pushSigning, err := boundedGitOptional(ctx, repoAbs, "config", "--get", "push.gpgSign")
	if err != nil {
		return ineligible("cannot_resolve_push_signing_config")
	}
	pushSigning = strings.ToLower(strings.TrimSpace(pushSigning))
	if pushSigning != "" && pushSigning != "false" && pushSigning != "no" && pushSigning != "never" {
		return ineligible("git_push_signing_config_not_supported")
	}
	pushOptions, err := boundedGitOptional(ctx, repoAbs, "config", "--get-all", "push.pushOption")
	if err != nil {
		return ineligible("cannot_resolve_push_option_config")
	}
	if strings.TrimSpace(pushOptions) != "" {
		return ineligible("git_push_option_config_not_supported")
	}
	mirror, err := boundedGitOptional(ctx, repoAbs, "config", "--bool", "--get", "remote."+remote+".mirror")
	if err != nil {
		return ineligible("cannot_resolve_remote_mirror_config")
	}
	if strings.EqualFold(strings.TrimSpace(mirror), "true") {
		return ineligible("git_push_remote_mirror_config_not_supported")
	}
	refspecs := positionals[1:]
	if len(refspecs) == 0 {
		return ineligible("explicit_git_push_refspec_required")
	}
	targets := make([]string, 0, len(refspecs)*2)
	for _, refspec := range refspecs {
		if strings.ContainsAny(refspec, "*?[") || strings.HasPrefix(refspec, "+") || strings.HasPrefix(refspec, ":") {
			return highRisk("unsafe_git_push_refspec")
		}
		parts := strings.SplitN(refspec, ":", 2)
		source, sourceOK := normalizeHeadRef(parts[0])
		destination := source
		destinationOK := sourceOK
		if len(parts) == 2 {
			destination, destinationOK = normalizeHeadRef(parts[1])
		}
		if !sourceOK || !destinationOK || !localGitBranchExists(ctx, repoAbs, source) {
			return ineligible("git_push_requires_explicit_local_branch_refspec")
		}
		if protectedDirectPushTarget(destination) {
			return highRisk("direct_push_to_protected_or_production_branch:" + destination)
		}
		targets = append(targets, "branch:"+source, "remote:"+remote+":"+destination)
	}
	return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_remote_write"}, Repositories: []string{repo, remoteRepo}, Targets: targets, Summary: "git push"}
}

func classifyGitHub(ctx context.Context, workspaceRoot string, args []string) Action {
	if len(args) < 2 || strings.ToLower(args[0]) != "pr" {
		return ineligible("only_gh_pr_commands_are_supported")
	}
	action := strings.ToLower(args[1])
	prArgs := args[2:]
	valueOptions := map[string]string{"--repo": "repo", "-R": "repo"}
	flagOptions := map[string]string{}
	requireSelector := false
	allowSelector := false

	switch action {
	case "create":
		valueOptions["--base"], valueOptions["-B"] = "base", "base"
		valueOptions["--head"], valueOptions["-H"] = "head", "head"
		valueOptions["--title"] = "title"
		valueOptions["--body"] = "body"
		flagOptions["--draft"] = "draft"
		flagOptions["--no-maintainer-edit"] = "no_maintainer_edit"
	case "merge":
		flagOptions["--merge"] = "merge"
		flagOptions["--squash"] = "squash"
		flagOptions["--rebase"] = "rebase"
		requireSelector, allowSelector = true, true
	case "view", "checks", "diff":
		requireSelector, allowSelector = true, true
	case "status":
		// Repository-wide read; no positional selector or interactive options.
	default:
		return ineligible("unsupported_gh_pr_action:" + action)
	}

	parsed, err := parseGHPRArguments(prArgs, valueOptions, flagOptions)
	if err != nil {
		return ineligible("unsupported_gh_pr_argument:" + err.Error())
	}
	if (!allowSelector && len(parsed.Positionals) != 0) || (allowSelector && len(parsed.Positionals) > 1) {
		return ineligible("unexpected_gh_pr_positional_argument")
	}
	selector := ""
	if len(parsed.Positionals) == 1 {
		selector = parsed.Positionals[0]
	}
	if requireSelector && !safeSelector(selector) {
		return ineligible("gh_pr_action_requires_explicit_numeric_selector")
	}
	repository, err := githubRepositoryForValue(parsed.Values["repo"])
	if err != nil {
		return ineligible("explicit_or_resolvable_github_repository_required")
	}
	prTarget := func() string {
		return "pr:" + strings.TrimPrefix(repository, "github:") + "#" + selector
	}

	switch action {
	case "create":
		base, head := parsed.Values["base"], parsed.Values["head"]
		if !safeGitName(base) || !safeGitName(head) || strings.TrimSpace(parsed.Values["title"]) == "" || strings.TrimSpace(parsed.Values["body"]) == "" {
			return ineligible("gh_pr_create_requires_explicit_safe_base_head_title_and_body")
		}
		return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"github_pr_write"}, Repositories: []string{repository}, Targets: []string{"pr:" + strings.TrimPrefix(repository, "github:") + ":create", "branch:" + base, "branch:" + head}, Summary: "gh pr create"}
	case "merge":
		strategies := 0
		for _, name := range []string{"merge", "squash", "rebase"} {
			if parsed.Flags[name] {
				strategies++
			}
		}
		if strategies != 1 {
			return ineligible("gh_pr_merge_requires_exactly_one_strategy")
		}
		metadata, metadataErr := resolvePullRequestMetadata(ctx, repository, selector)
		if metadataErr != nil || !safeGitName(metadata.BaseRefName) || !safeGitName(metadata.HeadRefName) {
			return ineligible("cannot_resolve_gh_pr_merge_base_and_head")
		}
		if protectedPRMergeTarget(metadata.BaseRefName) {
			return highRisk("pr_merge_to_production_branch:" + metadata.BaseRefName)
		}
		return Action{
			Eligible:     true,
			Risk:         RiskOrdinary,
			Classes:      []string{"github_pr_merge"},
			Repositories: []string{repository},
			Targets:      sortedUnique([]string{prTarget(), "branch:" + metadata.BaseRefName, "branch:" + metadata.HeadRefName}),
			Summary:      "gh pr merge",
		}
	case "view", "checks", "diff":
		return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_remote_read"}, Repositories: []string{repository}, Targets: []string{prTarget()}, Summary: "gh pr " + action}
	case "status":
		return Action{Eligible: true, Risk: RiskOrdinary, Classes: []string{"git_remote_read"}, Repositories: []string{repository}, Summary: "gh pr status"}
	default:
		return ineligible("unsupported_gh_pr_action:" + action)
	}
}

type ghPRArguments struct {
	Values      map[string]string
	Flags       map[string]bool
	Positionals []string
}

func parseGHPRArguments(args []string, valueOptions, flagOptions map[string]string) (ghPRArguments, error) {
	result := ghPRArguments{Values: map[string]string{}, Flags: map[string]bool{}}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		name, inlineValue, hasInlineValue := strings.Cut(arg, "=")
		if canonical, ok := valueOptions[name]; ok {
			value := inlineValue
			if !hasInlineValue {
				if index+1 >= len(args) {
					return ghPRArguments{}, fmt.Errorf("%s_requires_value", name)
				}
				index++
				value = args[index]
			}
			if strings.TrimSpace(value) == "" || result.Values[canonical] != "" {
				return ghPRArguments{}, fmt.Errorf("%s_missing_or_duplicate", canonical)
			}
			result.Values[canonical] = value
			continue
		}
		if canonical, ok := flagOptions[arg]; ok {
			if hasInlineValue || result.Flags[canonical] {
				return ghPRArguments{}, fmt.Errorf("%s_invalid_or_duplicate", canonical)
			}
			result.Flags[canonical] = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return ghPRArguments{}, fmt.Errorf("unknown_option_%s", arg)
		}
		result.Positionals = append(result.Positionals, arg)
	}
	return result, nil
}

func resolvePullRequestMetadata(ctx context.Context, repository, selector string) (pullRequestMetadata, error) {
	if resolver, ok := ctx.Value(pullRequestMetadataResolverContextKey{}).(pullRequestMetadataResolver); ok && resolver != nil {
		return resolver(ctx, repository, selector)
	}
	repoSlug := strings.TrimPrefix(repository, "github:")
	if repoSlug == repository || strings.TrimSpace(repoSlug) == "" || !safeSelector(selector) {
		return pullRequestMetadata{}, errors.New("invalid GitHub PR metadata request")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, grantExecutablePath(ctx, "gh"), "pr", "view", selector, "--repo", "github.com/"+repoSlug, "--json", "baseRefName,headRefName")
	command.Env = mergeGrantEnvironment(grantExecutionEnvironment(ctx), []string{"GH_PROMPT_DISABLED=1", "GH_PAGER="})
	output, err := command.Output()
	if err != nil {
		return pullRequestMetadata{}, err
	}
	var metadata pullRequestMetadata
	if err := json.Unmarshal(output, &metadata); err != nil {
		return pullRequestMetadata{}, err
	}
	if !safeGitName(metadata.BaseRefName) || !safeGitName(metadata.HeadRefName) {
		return pullRequestMetadata{}, errors.New("GitHub PR metadata returned unsafe base/head")
	}
	return metadata, nil
}

func resolveGitCommandDirectory(workspaceRoot, currentDir, operand string) (string, error) {
	rootAbs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", err
	}
	candidate := operand
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(currentDir, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	if _, err := workspaceRelative(rootAbs, candidate); err != nil {
		return "", err
	}
	if err := verifyResolvedWithinWorkspace(rootAbs, candidate); err != nil {
		return "", err
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("git -C target is not a directory")
	}
	return candidate, nil
}

func workspaceGitRepository(ctx context.Context, workspaceRoot, commandDir string) (string, string, error) {
	_, candidate, err := workspaceRepository(workspaceRoot, commandDir)
	if err != nil {
		return "", "", err
	}
	topLevel, err := boundedGit(ctx, candidate, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", err
	}
	topLevel = strings.TrimSpace(topLevel)
	if !filepath.IsAbs(topLevel) {
		topLevel = filepath.Join(candidate, topLevel)
	}
	topLevel, err = filepath.Abs(topLevel)
	if err != nil {
		return "", "", err
	}
	rootAbs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", "", err
	}
	relative, err := workspaceRelative(rootAbs, topLevel)
	if err != nil {
		return "", "", err
	}
	if err := verifyResolvedWithinWorkspace(rootAbs, topLevel); err != nil {
		return "", "", err
	}
	if err := repositoryGrantSafety(ctx, rootAbs, topLevel); err != nil {
		return "", "", err
	}
	repository, err := NormalizeRepository(filepath.ToSlash(relative))
	return repository, topLevel, err
}

func workspaceRepository(workspaceRoot, repoArg string) (string, string, error) {
	rootAbs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", "", err
	}
	repoAbs := repoArg
	if !filepath.IsAbs(repoAbs) {
		repoAbs = filepath.Join(rootAbs, repoArg)
	}
	repoAbs, err = filepath.Abs(repoAbs)
	if err != nil {
		return "", "", err
	}
	relative, err := workspaceRelative(rootAbs, repoAbs)
	if err != nil {
		return "", "", errors.New("repository escapes workspace")
	}
	if err := verifyResolvedWithinWorkspace(rootAbs, repoAbs); err != nil {
		return "", "", err
	}
	relative = filepath.ToSlash(filepath.Clean(relative))
	if relative == "" {
		relative = "."
	}
	repository, err := NormalizeRepository(relative)
	return repository, repoAbs, err
}

func commandWritePath(workspaceRoot, repoAbs, operand string) (string, error) {
	rootAbs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", err
	}
	if operand == "" || operand != strings.TrimSpace(operand) {
		return "", errors.New("empty or edge-whitespace path")
	}
	candidate := operand
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(repoAbs, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(rootAbs, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes workspace")
	}
	relative = filepath.ToSlash(filepath.Clean(relative))
	if relative != strings.TrimSpace(relative) {
		return "", errors.New("path contains unsupported edge whitespace")
	}
	if operand == "." || strings.HasSuffix(strings.ReplaceAll(operand, "\\", "/"), "/.") {
		if relative == "." {
			return "**", nil
		}
		return relative + "/**", nil
	}
	return relative, nil
}

func literalGitAddPath(ctx context.Context, repoAbs, commandDir, operand string) (string, error) {
	if operand == "" || operand != strings.TrimSpace(operand) {
		return "", errors.New("git add path contains unsupported edge whitespace")
	}
	candidate := operand
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(commandDir, candidate)
	}
	candidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(repoAbs, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("git add path must be a file inside the repository")
	}
	relative = filepath.ToSlash(filepath.Clean(relative))
	if relative == ".git" || strings.HasPrefix(relative, ".git/") {
		return "", errors.New("git metadata paths are not grant eligible")
	}
	if info, statErr := os.Stat(candidate); statErr == nil {
		if info.IsDir() {
			return "", errors.New("recursive git add directory is not grant eligible")
		}
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	}

	// A missing operand can represent an exact deleted file, but it can also
	// represent a deleted directory whose tracked descendants would be staged
	// recursively. Prove that every matching tracked path is the exact operand.
	tracked, err := boundedGit(ctx, repoAbs, "ls-files", "-z", "--", relative)
	if err != nil {
		return "", err
	}
	if len(tracked) > 1<<20 {
		return "", errors.New("git add tracked path set exceeds grant inspection limit")
	}
	for _, item := range strings.Split(tracked, "\x00") {
		if item == "" {
			continue
		}
		if filepath.ToSlash(filepath.Clean(item)) != relative {
			return "", errors.New("recursive git add path is not grant eligible")
		}
	}
	return relative, nil
}

func stagedGitPaths(ctx context.Context, workspaceRoot, repoAbs string) ([]string, error) {
	output, err := boundedGit(ctx, repoAbs, "diff", "--cached", "--name-only", "--no-renames", "-z")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for _, item := range strings.Split(output, "\x00") {
		if item == "" {
			continue
		}
		if hasUnsafePathText(item) {
			return nil, errors.New("staged path contains control characters")
		}
		if item != strings.TrimSpace(item) {
			return nil, errors.New("staged path contains unsupported edge whitespace")
		}
		normalized, pathErr := commandWritePath(workspaceRoot, repoAbs, item)
		if pathErr != nil {
			return nil, pathErr
		}
		result = append(result, normalized)
	}
	return sortedUnique(result), nil
}

func currentGitBranch(ctx context.Context, repoAbs string) (string, error) {
	output, err := boundedGit(ctx, repoAbs, "rev-parse", "--abbrev-ref", "HEAD")
	if err == nil {
		return strings.TrimSpace(output), nil
	}
	// An unborn branch has no HEAD object yet, but symbolic-ref still exposes
	// the branch that status/add/commit operate on. Detached HEAD does not take
	// this path because rev-parse succeeds with the literal HEAD marker.
	output, symbolicErr := boundedGit(ctx, repoAbs, "symbolic-ref", "--quiet", "--short", "HEAD")
	if symbolicErr != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

func resolveGitReadTarget(ctx context.Context, repoAbs, revision string) (string, string, error) {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		branch, err := currentGitBranch(ctx, repoAbs)
		if err != nil || branch == "HEAD" || !safeGitName(branch) {
			return "", "", errors.New("attached git branch required for grant-eligible read")
		}
		return "branch:" + branch, "", nil
	}

	if isFullGitObjectID(revision) {
		canonical := strings.ToLower(revision)
		resolved, err := boundedGit(ctx, repoAbs, "rev-parse", "--verify", "--quiet", canonical+"^{object}")
		if err != nil {
			return "", "", err
		}
		resolved = strings.ToLower(strings.TrimSpace(resolved))
		if !isFullGitObjectID(resolved) || resolved != canonical {
			return "", "", errors.New("full object ID did not resolve to itself")
		}
		return "object:" + canonical, canonical, nil
	}

	const branchPrefix = "refs/heads/"
	if !strings.HasPrefix(revision, branchPrefix) {
		return "", "", errors.New("grant-eligible git read target must use default HEAD, explicit refs/heads/<name>, or a full object ID")
	}
	branch := strings.TrimPrefix(revision, branchPrefix)
	if !safeGitName(branch) || !localGitBranchExists(ctx, repoAbs, branch) {
		return "", "", errors.New("explicit git branch target does not exist or is unsafe")
	}
	canonical := branchPrefix + branch
	return "branch:" + branch, canonical, nil
}

func isFullGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F' {
			continue
		}
		return false
	}
	return true
}

func resolveGitRemote(ctx context.Context, workspaceRoot, repoAbs, remote string, forPush bool) (string, error) {
	args := []string{"remote", "get-url"}
	if forPush {
		args = append(args, "--push")
	}
	args = append(args, "--all", remote)
	output, err := boundedGit(ctx, repoAbs, args...)
	if err != nil {
		return "", err
	}
	urls := make([]string, 0, 1)
	for _, item := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if item = strings.TrimSpace(item); item != "" {
			urls = append(urls, item)
		}
	}
	if len(urls) != 1 {
		return "", errors.New("grant-eligible git remote must resolve to exactly one URL")
	}
	commandKey := "uploadpack"
	if forPush {
		commandKey = "receivepack"
	}
	if value, configErr := boundedGitOptional(ctx, repoAbs, "config", "--get", "remote."+remote+"."+commandKey); configErr != nil {
		return "", configErr
	} else if strings.TrimSpace(value) != "" {
		return "", fmt.Errorf("remote.%s.%s command override is not grant eligible", remote, commandKey)
	}
	if value, configErr := boundedGitOptional(ctx, repoAbs, "config", "--get", "remote."+remote+".vcs"); configErr != nil {
		return "", configErr
	} else if strings.TrimSpace(value) != "" {
		return "", fmt.Errorf("remote.%s.vcs helper override is not grant eligible", remote)
	}
	repository, err := canonicalRemoteRepository(workspaceRoot, repoAbs, urls[0])
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(repository, "github:") {
		if err := networkCredentialHelperGrantSafety(ctx, repoAbs); err != nil {
			return "", err
		}
		for _, name := range []string{"GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS"} {
			if value, _ := environmentValue(grantExecutionEnvironment(ctx), name); strings.TrimSpace(value) != "" {
				return "", fmt.Errorf("%s is not grant eligible for network remotes", name)
			}
		}
		for _, key := range []string{"core.sshCommand", "core.gitProxy", "core.askPass", "remote." + remote + ".proxy"} {
			if value, configErr := boundedGitOptional(ctx, repoAbs, "config", "--get", key); configErr != nil {
				return "", configErr
			} else if strings.TrimSpace(value) != "" {
				return "", fmt.Errorf("Git command override %s is not grant eligible", key)
			}
		}
	}
	if strings.HasPrefix(repository, "workspace:") {
		rootAbs, absErr := filepath.Abs(workspaceRoot)
		if absErr != nil {
			return "", absErr
		}
		localPath := filepath.Join(rootAbs, filepath.FromSlash(strings.TrimPrefix(repository, "workspace:")))
		if err := repositoryGrantSafety(ctx, rootAbs, localPath); err != nil {
			return "", err
		}
	}
	return repository, nil
}

func networkCredentialHelperGrantSafety(ctx context.Context, repoAbs string) error {
	urlScoped, err := boundedGitOptional(ctx, repoAbs, "config", "--get-regexp", `^credential\..+\.helper$`)
	if err != nil {
		return err
	}
	if strings.TrimSpace(urlScoped) != "" {
		return errors.New("URL-scoped credential helper configuration is not grant eligible")
	}

	configured, err := boundedGitOptional(ctx, repoAbs, "config", "--show-origin", "--get-all", "credential.helper")
	if err != nil {
		return err
	}
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(configured, "\r\n", "\n"), "\n")
	if runtime.GOOS != "windows" || len(lines) != 1 {
		return errors.New("configured credential helper is not grant eligible")
	}
	origin, helper, ok := strings.Cut(lines[0], "\t")
	if !ok || strings.TrimSpace(helper) != "manager" || !strings.HasPrefix(origin, "file:") {
		return errors.New("configured credential helper is not grant eligible")
	}
	root, err := trustedGitInstallationRoot(grantExecutablePath(ctx, "git"))
	if err != nil {
		return err
	}
	originPath := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(strings.TrimSpace(origin), "file:")))
	expectedConfig := filepath.Clean(filepath.Join(root, "etc", "gitconfig"))
	if !strings.EqualFold(originPath, expectedConfig) {
		return errors.New("credential helper must come from the trusted Git system config")
	}
	helperPath := filepath.Join(root, "mingw64", "bin", "git-credential-manager.exe")
	info, err := os.Stat(helperPath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("trusted Git credential manager is unavailable")
	}
	trustedBinary, err := executableHasTrustedBinaryFormat(helperPath)
	if err != nil {
		return err
	}
	if !trustedBinary {
		return errors.New("trusted Git credential manager has an unsupported binary format")
	}
	return nil
}

func canonicalRemoteRepository(workspaceRoot, repoAbs, remote string) (string, error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", errors.New("empty git remote is not grant eligible")
	}
	if strings.Contains(remote, "::") {
		return "", errors.New("git remote-helper transport syntax is not grant eligible")
	}
	if !strings.Contains(remote, "://") && hasAmbiguousGitScpSyntax(remote) {
		return "", errors.New("ambiguous scp-like git remote is not grant eligible")
	}
	if strings.Contains(remote, "://") {
		parsed, err := url.Parse(remote)
		if err != nil {
			return "", errors.New("invalid git remote URL")
		}
		scheme := strings.ToLower(parsed.Scheme)
		switch scheme {
		case "https":
			if !strings.EqualFold(parsed.Hostname(), "github.com") || parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				return "", errors.New("grant-eligible HTTPS remotes must be canonical github.com URLs")
			}
			return NormalizeRepository("github:" + strings.TrimPrefix(parsed.Path, "/"))
		case "ssh":
			return "", errors.New("SSH git remotes are not grant eligible in Stage V1")
		case "file":
			if parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return "", errors.New("grant-eligible file remotes must be local paths without host, query, or fragment")
			}
			remote = parsed.Path
			if runtime.GOOS == "windows" && len(remote) >= 3 && remote[0] == '/' && remote[2] == ':' {
				remote = remote[1:]
			}
		default:
			return "", errors.New("unsupported git remote protocol for grant reuse")
		}
	}
	candidate := remote
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(repoAbs, candidate)
	}
	rootAbs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", err
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := workspaceRelative(rootAbs, candidate)
	if err != nil {
		return "", errors.New("remote repository is outside workspace")
	}
	if err := verifyResolvedWithinWorkspace(rootAbs, candidate); err != nil {
		return "", err
	}
	return NormalizeRepository(filepath.ToSlash(relative))
}

func hasAmbiguousGitScpSyntax(remote string) bool {
	colon := strings.IndexByte(remote, ':')
	if colon <= 0 {
		return false
	}
	if isWindowsAbsoluteDrivePath(remote) {
		return false
	}
	prefix := remote[:colon]
	return !strings.ContainsAny(prefix, `/\\`)
}

func isWindowsAbsoluteDrivePath(value string) bool {
	if runtime.GOOS != "windows" || len(value) < 3 || value[1] != ':' || value[2] != '/' && value[2] != '\\' {
		return false
	}
	letter := value[0]
	return letter >= 'A' && letter <= 'Z' || letter >= 'a' && letter <= 'z'
}

func workspaceRelative(rootAbs, candidateAbs string) (string, error) {
	relative, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes workspace")
	}
	return relative, nil
}

func verifyResolvedWithinWorkspace(rootAbs, candidateAbs string) error {
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return fmt.Errorf("resolve workspace path: %w", err)
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidateAbs)
	if err != nil {
		return fmt.Errorf("resolve repository path: %w", err)
	}
	if _, err := workspaceRelative(resolvedRoot, resolvedCandidate); err != nil {
		return errors.New("resolved repository path escapes workspace")
	}
	return nil
}

func githubRepositoryForValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("grant-eligible gh pr commands require explicit --repo")
	}
	if host := strings.TrimSpace(os.Getenv("GH_HOST")); host != "" && !strings.EqualFold(host, "github.com") {
		return "", errors.New("GH_HOST must be unset or github.com for grant-eligible gh pr commands")
	}
	return NormalizeRepository("github:" + value)
}

func repositoryGrantSafety(ctx context.Context, workspaceRoot, repoAbs string) error {
	for _, command := range []struct {
		args []string
		name string
	}{
		{args: []string{"rev-parse", "--absolute-git-dir"}, name: "git-dir"},
		{args: []string{"rev-parse", "--path-format=absolute", "--git-common-dir"}, name: "git-common-dir"},
	} {
		value, err := boundedGit(ctx, repoAbs, command.args...)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", command.name, err)
		}
		pathValue := strings.TrimSpace(value)
		if !filepath.IsAbs(pathValue) {
			pathValue = filepath.Join(repoAbs, pathValue)
		}
		pathValue, err = filepath.Abs(pathValue)
		if err != nil {
			return err
		}
		if _, err := workspaceRelative(workspaceRoot, pathValue); err != nil {
			return fmt.Errorf("%s escapes workspace", command.name)
		}
		if err := verifyResolvedWithinWorkspace(workspaceRoot, pathValue); err != nil {
			return fmt.Errorf("%s escapes workspace: %w", command.name, err)
		}
	}
	hasSubmodules, err := repositoryHasSubmoduleState(ctx, repoAbs)
	if err != nil {
		return fmt.Errorf("inspect repository submodule state: %w", err)
	}
	if hasSubmodules {
		return errors.New("repositories with submodules are not grant eligible")
	}
	if value, err := boundedGitOptional(ctx, repoAbs, "config", "--get", "core.hooksPath"); err != nil {
		return err
	} else if strings.TrimSpace(value) != "" {
		return errors.New("custom core.hooksPath is not grant eligible")
	}
	if value, err := boundedGitOptional(ctx, repoAbs, "config", "--get", "core.fsmonitor"); err != nil {
		return err
	} else if normalized := strings.ToLower(strings.TrimSpace(value)); normalized != "" && normalized != "false" && normalized != "0" {
		return errors.New("core.fsmonitor is not grant eligible")
	}
	if value, _ := environmentValue(grantExecutionEnvironment(ctx), "GIT_EXTERNAL_DIFF"); strings.TrimSpace(value) != "" {
		return errors.New("GIT_EXTERNAL_DIFF is not grant eligible")
	}
	hooksPath, err := boundedGit(ctx, repoAbs, "rev-parse", "--git-path", "hooks")
	if err != nil {
		return err
	}
	hooksPath = strings.TrimSpace(hooksPath)
	if !filepath.IsAbs(hooksPath) {
		hooksPath = filepath.Join(repoAbs, hooksPath)
	}
	entries, err := os.ReadDir(hooksPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(strings.ToLower(entry.Name()), ".sample") {
			continue
		}
		return fmt.Errorf("active git hook %q is not grant eligible", entry.Name())
	}
	return nil
}

func repositoryHasSubmoduleState(ctx context.Context, repoAbs string) (bool, error) {
	bare, err := boundedGit(ctx, repoAbs, "rev-parse", "--is-bare-repository")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(bare)) {
	case "true":
		return false, nil
	case "false":
		// Continue with worktree, index, tree, and effective configuration checks.
	default:
		return false, errors.New("cannot determine whether repository is bare")
	}

	if _, statErr := os.Stat(filepath.Join(repoAbs, ".gitmodules")); statErr == nil {
		return true, nil
	} else if !os.IsNotExist(statErr) {
		return false, statErr
	}
	indexEntries, err := boundedGit(ctx, repoAbs, "ls-files", "--stage", "-z")
	if err != nil {
		return false, err
	}
	if hasGitlink, parseErr := gitMetadataHasGitlink(indexEntries); parseErr != nil || hasGitlink {
		return hasGitlink, parseErr
	}
	head, err := boundedGitOptional(ctx, repoAbs, "rev-parse", "--verify", "--quiet", "HEAD")
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(head) != "" {
		treeEntries, treeErr := boundedGit(ctx, repoAbs, "ls-tree", "-r", "-z", "HEAD")
		if treeErr != nil {
			return false, treeErr
		}
		if hasGitlink, parseErr := gitMetadataHasGitlink(treeEntries); parseErr != nil || hasGitlink {
			return hasGitlink, parseErr
		}
	}
	submoduleConfig, err := boundedGitOptional(ctx, repoAbs, "config", "--name-only", "--get-regexp", "^submodule\\..*\\.")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(submoduleConfig) != "", nil
}

func gitMetadataHasGitlink(output string) (bool, error) {
	if len(output) > 4<<20 {
		return false, errors.New("git metadata exceeds submodule inspection limit")
	}
	items := strings.Split(output, "\x00")
	if len(items) > 20001 {
		return false, errors.New("git metadata entry count exceeds submodule inspection limit")
	}
	for _, item := range items {
		if strings.HasPrefix(item, "160000 ") {
			return true, nil
		}
	}
	return false, nil
}

func repositoryUsesExternalAttributes(ctx context.Context, repoAbs, source string) (bool, error) {
	var paths string
	var err error
	if strings.TrimSpace(source) == "" {
		paths, err = boundedGit(ctx, repoAbs, "ls-files", "-co", "--exclude-standard", "-z")
	} else {
		paths, err = boundedGit(ctx, repoAbs, "ls-tree", "-r", "--name-only", "-z", source)
	}
	if err != nil {
		return false, err
	}
	if len(paths) > 1<<20 {
		return false, errors.New("git attribute path set exceeds grant inspection limit")
	}
	pathItems := strings.Split(paths, "\x00")
	if len(pathItems) > 20001 {
		return false, errors.New("git attribute path count exceeds grant inspection limit")
	}
	if strings.Trim(paths, "\x00") == "" {
		return false, nil
	}

	var output string
	if strings.TrimSpace(source) == "" {
		output, err = boundedGitWithInput(ctx, repoAbs, paths, "check-attr", "-z", "--stdin", "filter", "diff")
	} else {
		output, err = boundedGitAttributesFromTree(ctx, repoAbs, source, paths)
	}
	if err != nil {
		return false, err
	}
	if len(output) > 4<<20 {
		return false, errors.New("git attribute result exceeds grant inspection limit")
	}
	fields := strings.Split(output, "\x00")
	if len(fields) > 0 && fields[len(fields)-1] == "" {
		fields = fields[:len(fields)-1]
	}
	if len(fields)%3 != 0 {
		return false, errors.New("malformed git check-attr response")
	}
	for index := 0; index < len(fields); index += 3 {
		attribute := strings.ToLower(strings.TrimSpace(fields[index+1]))
		value := strings.TrimSpace(fields[index+2])
		normalized := strings.ToLower(value)
		if normalized == "" || normalized == "unspecified" || normalized == "unset" {
			continue
		}
		var suffixes []string
		switch attribute {
		case "filter":
			suffixes = []string{"clean", "smudge", "process"}
		case "diff":
			if normalized == "set" {
				continue
			}
			suffixes = []string{"command", "textconv"}
		default:
			continue
		}
		if hasUnsafePathText(value) || strings.ContainsAny(value, " \t") {
			return true, nil
		}
		for _, suffix := range suffixes {
			configured, configErr := boundedGitOptional(ctx, repoAbs, "config", "--get", attribute+"."+value+"."+suffix)
			if configErr != nil {
				return false, configErr
			}
			if strings.TrimSpace(configured) != "" {
				return true, nil
			}
		}
	}
	return false, nil
}

func boundedGitAttributesFromTree(ctx context.Context, repoAbs, source, input string) (string, error) {
	tempDir, err := os.MkdirTemp("", "mcpx-authorization-index-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)

	indexPath := filepath.Join(tempDir, "index")
	environment := []string{"GIT_INDEX_FILE=" + indexPath}
	if _, err := boundedGitWithEnvInput(ctx, repoAbs, environment, "", "read-tree", source); err != nil {
		return "", fmt.Errorf("populate temporary git index: %w", err)
	}
	output, err := boundedGitWithEnvInput(ctx, repoAbs, environment, input, "check-attr", "--cached", "-z", "--stdin", "filter", "diff")
	if err != nil {
		return "", fmt.Errorf("inspect target-tree git attributes: %w", err)
	}
	return output, nil
}

func boundedGitWithInput(ctx context.Context, repoAbs, input string, args ...string) (string, error) {
	return boundedGitWithEnvInput(ctx, repoAbs, nil, input, args...)
}

func boundedGitWithEnvInput(ctx context.Context, repoAbs string, environment []string, input string, args ...string) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	commandArgs := append([]string{"-C", repoAbs}, args...)
	command := exec.CommandContext(bounded, grantExecutablePath(ctx, "git"), commandArgs...)
	command.Env = mergeGrantEnvironment(grantExecutionEnvironment(ctx), environment)
	if input != "" {
		command.Stdin = strings.NewReader(input)
	}
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func hasGitAttribute(ctx context.Context, repoAbs, attribute, pathValue string) bool {
	output, err := boundedGit(ctx, repoAbs, "check-attr", "-z", attribute, "--", pathValue)
	if err != nil {
		return true
	}
	parts := strings.Split(output, "\x00")
	if len(parts) < 3 {
		return true
	}
	value := strings.ToLower(strings.TrimSpace(parts[2]))
	return value != "" && value != "unspecified" && value != "unset"
}

func boundedGitOptional(ctx context.Context, repoAbs string, args ...string) (string, error) {
	output, err := boundedGit(ctx, repoAbs, args...)
	if err == nil {
		return output, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return "", nil
	}
	return "", err
}

func boundedGit(ctx context.Context, repoAbs string, args ...string) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	commandArgs := append([]string{"-C", repoAbs}, args...)
	command := exec.CommandContext(bounded, grantExecutablePath(ctx, "git"), commandArgs...)
	command.Env = grantExecutionEnvironment(ctx)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func obviousHighRisk(words []string) string {
	if len(words) == 0 {
		return "empty_command"
	}
	first := executableName(words[0])
	highRiskExecutables := map[string]bool{
		"rm": true, "rmdir": true, "shred": true, "sdelete": true, "del": true, "erase": true,
		"remove-item": true, "clear-content": true, "format": true,
		"kubectl": true, "helm": true, "terraform": true, "ansible": true,
		"aws": true, "gcloud": true, "az": true, "stripe": true, "paypal": true,
		"netsh": true, "iptables": true, "nft": true, "ufw": true, "route": true, "nmcli": true,
		"systemctl": true, "service": true, "sc": true, "ssh": true, "scp": true, "sftp": true,
	}
	if highRiskExecutables[first] {
		return "high_risk_executable:" + first
	}
	joined := strings.ToLower(strings.Join(words, " "))
	for _, marker := range []string{" credential", " credentials", " secret", " token", " payment", " charge", " deploy", " deployment", " production", " publish", " release"} {
		if strings.Contains(" "+joined, marker) {
			return "high_risk_intent:" + strings.TrimSpace(marker)
		}
	}
	if first == "gh" && len(words) > 1 {
		sub := strings.ToLower(words[1])
		if sub == "auth" || sub == "secret" || sub == "variable" || sub == "release" || sub == "repo" && stringSliceContains(words, "delete") {
			return "high_risk_gh_command:" + sub
		}
	}
	return ""
}

func containsUnsupportedShellSyntax(raw string) bool {
	// Grant reuse must classify the same literal argv that the platform shell
	// will execute. MCPX uses Bash on Unix and cmd.exe on Windows, whose
	// expansion and quoting rules diverge for these characters. Fall back to
	// exact-command confirmation rather than trying to emulate both shells.
	for _, marker := range []string{
		"`", "$", "%", "!", "^", "|", ">", "<", "\r", "\n",
		"\\", "'", "*", "?", "[", "]", "{", "}", "~", "(", ")",
	} {
		if strings.Contains(raw, marker) {
			return true
		}
	}
	return false
}

func shellWords(input string) ([]string, error) {
	var result []string
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			result = append(result, current.String())
			current.Reset()
		}
	}
	runes := []rune(input)
	for index, r := range runes {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			nextEscapable := index+1 < len(runes) && (unicode.IsSpace(runes[index+1]) || runes[index+1] == '\\' || runes[index+1] == '\'' || runes[index+1] == '"')
			if nextEscapable {
				escaped = true
				continue
			}
			current.WriteRune(r)
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		current.WriteRune(r)
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated quote or escape")
	}
	flush()
	return result, nil
}

func optionValue(args []string, names ...string) string {
	nameSet := map[string]bool{}
	for _, name := range names {
		nameSet[name] = true
	}
	for index, arg := range args {
		for name := range nameSet {
			if arg == name && index+1 < len(args) {
				return strings.TrimSpace(args[index+1])
			}
			if strings.HasPrefix(arg, name+"=") {
				return strings.TrimSpace(strings.TrimPrefix(arg, name+"="))
			}
		}
	}
	return ""
}

func firstPositional(args []string, valueOptions map[string]bool) string {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if valueOptions[arg] {
			index++
			continue
		}
		if strings.Contains(arg, "=") && valueOptions[strings.SplitN(arg, "=", 2)[0]] {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func hasUnsafePathText(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) >= 0
}

func normalizeHeadRef(value string) (string, bool) {
	if value != strings.TrimSpace(value) || value == "" {
		return "", false
	}
	if strings.HasPrefix(value, "refs/") {
		if !strings.HasPrefix(value, "refs/heads/") {
			return "", false
		}
		value = strings.TrimPrefix(value, "refs/heads/")
	}
	return value, safeGitName(value)
}

func localGitBranchExists(ctx context.Context, repoAbs, branch string) bool {
	if !safeGitName(branch) {
		return false
	}
	_, err := boundedGit(ctx, repoAbs, "show-ref", "--verify", "--quiet", "refs/heads/"+branch)
	return err == nil
}

func safeGitName(value string) bool {
	if value != strings.TrimSpace(value) {
		return false
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 200 || strings.HasPrefix(value, "-") || strings.Contains(value, "..") || strings.ContainsAny(value, " ~^:?*[\\\r\n\x00") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, "/") {
		return false
	}
	return true
}

func safeSelector(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 20 {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func protectedPRMergeTarget(branch string) bool {
	lower := strings.ToLower(strings.TrimSpace(branch))
	return lower == "production" || lower == "prod" || strings.HasPrefix(lower, "release/")
}

func protectedDirectPushTarget(branch string) bool {
	lower := strings.ToLower(strings.TrimSpace(branch))
	return lower == "main" || lower == "master" || lower == "develop" || lower == "production" || lower == "prod" || strings.HasPrefix(lower, "release/")
}

func isShortNumericGitLogLimit(value string) bool {
	if len(value) < 2 || value[0] != '-' {
		return false
	}
	for _, char := range value[1:] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func trustedGrantExecutable(value string) (string, bool) {
	// Grant classification must describe the same executable token the shell
	// will run. Paths, wrappers, aliases and explicit extensions fall back to
	// exact-command confirmation instead of being normalized into git/gh/go.
	switch value {
	case "git", "gh", "go":
		return value, true
	default:
		return "", false
	}
}

func executableName(value string) string {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(value)))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedUniqueExact(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ReplaceAll(value, "\\", "/")
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func highRisk(reason string) Action {
	return Action{Eligible: false, Risk: "high", Reasons: []string{reason}}
}

func ineligible(reason string) Action {
	return Action{Eligible: false, Risk: RiskOrdinary, Reasons: []string{reason}}
}
