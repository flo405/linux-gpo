package git

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const deviceKeyPath = "/etc/lgpo/device.key"

// Ensure syncs the repo to dir at the given branch.
// Flows:
//  - If repo is SSH (git@...), always use /etc/lgpo/device.key and assert read-only.
//  - Else try HTTPS as-is; on auth error, fall back to SSH with device key and assert read-only.
func Ensure(repo, branch, dir string) (string, error) {
	if isSSHURL(repo) {
		commit, err := ensureWith(repo, branch, dir, sshEnv())
		if err != nil { return "", err }
		readonly, checkErr := assertReadOnly(dir)
		if checkErr != nil { return "", fmt.Errorf("read-only check failed: %v", checkErr) }
		if !readonly { return "", errors.New("credentials appear to be WRITE-capable; refusing to proceed") }
		return commit, nil
	}

	// HTTPS first
	commit, err := ensureWith(repo, branch, dir, nil)
	if err == nil { return commit, nil }

	// If that failed and looks like a private GitHub repo with https, try SSH fallback
	if strings.HasPrefix(repo, "https://github.com/") || strings.HasPrefix(repo, "http://github.com/") {
		sshURL := httpsToSSH(repo)
		commit, sshErr := ensureWith(sshURL, branch, dir, sshEnv())
		if sshErr == nil {
			if readonly, checkErr := assertReadOnly(dir); checkErr != nil {
				return "", fmt.Errorf("repo synced but read-only check failed: %v", checkErr)
			} else if !readonly {
				return "", errors.New("credentials appear to be WRITE-capable; refusing to proceed")
			}
			return commit, nil
		}
		if isAuthError(err.Error()) {
			return "", fmt.Errorf("failed to access private repo via SSH deploy key: %v", sshErr)
		}
	}
	return "", err
}

func ensureWith(repo, branch, dir string, extraEnv []string) (string, error) {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		if out, err := cmdEnv(extraEnv, "git", "-C", dir, "fetch", "--depth", "1", "origin", branch); err != nil {
			return "", fmt.Errorf("git fetch: %v: %s", err, out)
		}
		if out, err := cmdEnv(extraEnv, "git", "-C", dir, "reset", "--hard", "origin/"+branch); err != nil {
			return "", fmt.Errorf("git reset: %v: %s", err, out)
		}
	} else {
		if err := os.MkdirAll(dir, 0755); err != nil { return "", err }
		if out, err := cmdEnv(extraEnv, "git", "clone", "--depth", "1", "--branch", branch, repo, dir); err != nil {
			return "", fmt.Errorf("git clone: %v: %s", err, out)
		}
	}
	out, err := cmdEnv(extraEnv, "git", "-C", dir, "rev-parse", "HEAD")
	if err != nil { return "", err }
	return strings.TrimSpace(out), nil
}

func cmdEnv(extraEnv []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func isSSHURL(u string) bool {
	return strings.HasPrefix(u, "git@") || strings.HasPrefix(u, "ssh://")
}

func httpsToSSH(u string) string {
	// https://github.com/ORG/REPO(.git) -> git@github.com:ORG/REPO.git
	s := strings.TrimPrefix(u, "https://github.com/")
	s = strings.TrimPrefix(s, "http://github.com/")
	s = strings.TrimSuffix(s, ".git")
	return "git@github.com:" + s + ".git"
}

func sshEnv() []string {
	// no pinning requested; accept-new to avoid prompts on first contact
	return []string{`GIT_SSH_COMMAND=ssh -i ` + deviceKeyPath + ` -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new`}
}

func assertReadOnly(dir string) (bool, error) {
	// Push dry-run should fail with permission-related error when using read-only deploy key
	ref := "refs/heads/lgpo-perm-check-" + randHex(6)
	out, err := cmdEnv(sshEnv(), "git", "-C", dir, "push", "--dry-run", "origin", "HEAD:"+ref)
	if err == nil {
		// Exit code 0 → push appears permitted
		return false, nil
	}
	// Look for common permission-denied signals from GitHub
	deniedRe := regexp.MustCompile(`(?i)(permission denied|write access to repository not granted|read[- ]only|deploy key|access denied)`)
	if deniedRe.MatchString(out) {
		return true, nil
	}
	// Other errors (network, repo not found). Treat as inconclusive.
	return false, fmt.Errorf("unexpected push dry-run error: %s", strings.TrimSpace(out))
}

func isAuthError(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "permission") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "authorization")
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
