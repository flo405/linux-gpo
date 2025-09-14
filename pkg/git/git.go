package git

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
)

func Ensure(repo, branch, dir string) (string, error) {
    if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
        if out, err := exec.Command("git", "-C", dir, "fetch", "--depth", "1", "origin", branch).CombinedOutput(); err != nil {
            return "", fmt.Errorf("git fetch: %v: %s", err, string(out))
        }
        if out, err := exec.Command("git", "-C", dir, "reset", "--hard", "origin/"+branch).CombinedOutput(); err != nil {
            return "", fmt.Errorf("git reset: %v: %s", err, string(out))
        }
    } else {
        if err := os.MkdirAll(dir, 0755); err != nil { return "", err }
        if out, err := exec.Command("git", "clone", "--depth", "1", "--branch", branch, repo, dir).CombinedOutput(); err != nil {
            return "", fmt.Errorf("git clone: %v: %s", err, string(out))
        }
    }
    out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").CombinedOutput()
    if err != nil { return "", err }
    return strings.TrimSpace(string(out)), nil
}
