package authorization

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
)

// Only the literal helper chain installed by gh auth setup-git is recognized.
// Never execute a helper to discover whether it is trusted.
func githubCLIURLHelpersGrantSafety(ctx context.Context, repoAbs string) error {
	configured, err := boundedGitOptional(ctx, repoAbs, "config", "-z", "--show-scope", "--show-origin", "--get-regexp", `^credential\..+\.helper$`)
	if err != nil || configured == "" {
		return err
	}
	if runtime.GOOS != "windows" {
		return errors.New("URL-scoped credential helpers require the supported Windows GitHub CLI chain")
	}
	environment := grantExecutionEnvironment(ctx)
	home, _ := environmentValue(environment, "HOME")
	if home == "" {
		home, _ = environmentValue(environment, "USERPROFILE")
	}
	if !filepath.IsAbs(home) {
		return errors.New("GitHub CLI helper requires an absolute user home")
	}
	globalConfig := filepath.Clean(filepath.Join(home, ".gitconfig"))
	fields := strings.Split(configured, "\x00")
	if fields[len(fields)-1] != "" || (len(fields)-1)%3 != 0 {
		return errors.New("malformed scoped credential helper configuration")
	}
	chains := make(map[string][]string)
	for index := 0; index < len(fields)-1; index += 3 {
		scope, origin := fields[index], fields[index+1]
		key, value, ok := strings.Cut(fields[index+2], "\n")
		if !ok || scope != "global" || !strings.HasPrefix(origin, "file:") {
			return errors.New("GitHub CLI helper must come from the user global config")
		}
		originPath := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(origin, "file:")))
		if !strings.EqualFold(originPath, globalConfig) {
			return errors.New("included credential helpers are not grant eligible")
		}
		if key != "credential.https://github.com.helper" && key != "credential.https://gist.github.com.helper" {
			return errors.New("unsupported credential helper URL scope")
		}
		chains[key] = append(chains[key], value)
	}
	if len(chains["credential.https://github.com.helper"]) != 2 {
		return errors.New("GitHub CLI helper requires exactly a reset and one helper")
	}
	gh, err := resolveGrantExecutable(ctx, repoAbs, "gh")
	if err != nil {
		return err
	}
	// A single quoted absolute path and fixed arguments are the entire grammar.
	if strings.ContainsAny(gh, "'\r\n") {
		return errors.New("GitHub CLI path cannot be represented by the supported helper grammar")
	}
	expected := "!'" + gh + "' auth git-credential"
	expectedSlashes := "!'" + filepath.ToSlash(gh) + "' auth git-credential"
	for _, chain := range chains {
		if len(chain) != 2 || chain[0] != "" || (chain[1] != expected && chain[1] != expectedSlashes) {
			return errors.New("unsupported GitHub CLI credential helper chain")
		}
	}
	return nil
}
