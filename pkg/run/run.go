// pkg/run/run.go
package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lgpo-org/lgpod/pkg/config"
	dc "github.com/lgpo-org/lgpod/pkg/dconf"
	"github.com/lgpo-org/lgpod/pkg/facts"
	"github.com/lgpo-org/lgpod/pkg/git"
	"github.com/lgpo-org/lgpod/pkg/inventory"
	lglog "github.com/lgpo-org/lgpod/pkg/log"
	mp "github.com/lgpo-org/lgpod/pkg/modprobe"
	pk "github.com/lgpo-org/lgpod/pkg/polkit"
	"github.com/lgpo-org/lgpod/pkg/selector"
	"github.com/lgpo-org/lgpod/pkg/status"
)

type managedItem struct {
	Path string `json:"path"`
}
type managedState struct {
	Version int           `json:"version"`
	Items   []managedItem `json:"items"`
}

type Runner struct {
	cfg       *config.Config
	log       *lglog.Logger
	lastFacts map[string]string
	lastTags  map[string]string
}

func New(cfg *config.Config, l *lglog.Logger) *Runner {
	return &Runner{cfg: cfg, log: l}
}

func (r *Runner) managedPath() string {
	// put it next to status.json
	return filepath.Join(filepath.Dir(r.cfg.StatusFile), "managed.json")
}
func (r *Runner) loadManaged() managedState {
	var s managedState
	b, err := os.ReadFile(r.managedPath())
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, &s)
	return s
}
func (r *Runner) saveManaged(items []managedItem) {
	s := managedState{Version: 1, Items: items}
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(r.managedPath(), b, 0o644)
}

func (r *Runner) Facts() map[string]string {
	if r.lastFacts == nil {
		r.lastFacts = facts.Discover()
	}
	return r.lastFacts
}

func (r *Runner) Tags() map[string]string {
	if r.lastTags == nil {
		r.lastTags = loadTags(r.cfg.TagsDir)
	}
	return r.lastTags
}

func (r *Runner) ReadStatus() (status.Status, error) {
	return status.Read(r.cfg.StatusFile)
}

func (r *Runner) RunOnce(ctx context.Context, dry bool, trigger string) error {
	start := time.Now()

	// 1) Refresh facts each run
	r.lastFacts = facts.Discover()

	// 2) Ensure the repo cache is up-to-date (policies + inventory)
	commit, err := git.Ensure(r.cfg.Repo, r.cfg.Branch, r.cfg.CacheDir)
	if err != nil {
		// Enrollment-friendly guidance for private repos or auth/permission issues
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "permission") || strings.Contains(lower, "access") || strings.Contains(lower, "auth") {
			// Try to compute device hash and load OpenSSH public key for admin enrollment
			hash, _, _ := inventory.ComputeDeviceHashPreferPub("/etc/lgpo/device.key")
			pub := ""
			if b, readErr := os.ReadFile("/etc/lgpo/device.key.pub"); readErr == nil {
				pub = strings.TrimSpace(string(b))
			}
			r.log.Warn("enrollment",
				"hint", "Private policy repo? Add this device as READ-ONLY deploy key and put its hash into inventory/devices.yml",
				"repo", r.cfg.Repo,
				"branch", r.cfg.Branch,
				"device", hash,
				"pubkey", pub,
			)
		}
		return err
	}

	// 3) Sync inventory → write authoritative tags from inventory/devices.yml
	deviceHash, wrote, invErr := inventory.SyncInventoryTags(
		r.cfg.CacheDir,
		r.cfg.TagsDir,
		"/etc/lgpo/device.key",
	)
	if invErr != nil {
		r.log.Warn("inventory", invErr.Error(), "device", deviceHash)
	} else {
		r.log.Warn("inventory", "synced", "device", deviceHash, "wrote", fmt.Sprintf("%d", wrote))
	}

	// 4) Load tags AFTER syncing inventory so policy logic sees fresh tags
	r.lastTags = loadTags(r.cfg.TagsDir)

	// 5) Evaluate policies
	polDir := filepath.Join(r.cfg.CacheDir, r.cfg.PoliciesDir())

	var toApply []applyItem
	dconfTouched := false
	initramfsTouched := false

	desiredPaths := map[string]struct{}{}
	desiredManaged := make([]managedItem, 0, 64)

	_ = filepath.WalkDir(polDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yml") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			r.log.Warn("read", err.Error(), "file", path)
			return nil
		}

		// Peek kind
		var hdr struct{ Kind string `yaml:"kind"` }
		if err := yaml.Unmarshal(b, &hdr); err != nil {
			r.log.Warn("yaml", err.Error(), "file", path)
			return nil
		}

		switch hdr.Kind {
		case "PolkitPolicy":
			var p pk.Policy
			if err := yaml.Unmarshal(b, &p); err != nil {
				r.log.Warn("yaml", err.Error(), "file", path)
				return nil
			}
			sel := selector.Sel{
				Facts:         p.Selector.Facts,
				Tags:          p.Selector.Tags,
				HostnameRegex: p.Selector.HostnameRegex,
			}
			if !sel.Match(selector.Context{Facts: r.lastFacts, Tags: r.lastTags}) {
				return nil
			}
			js, _, err := pk.Render(&p)
			if err != nil {
				r.log.Warn("render", err.Error(), "file", path)
				return nil
			}
			tgt := "/etc/polkit-1/rules.d/60-lgpo-" + p.Metadata.Name + ".rules"
			toApply = append(toApply, applyItem{Path: tgt, Data: js, Mode: 0o644})
			desiredPaths[tgt] = struct{}{}
			desiredManaged = append(desiredManaged, managedItem{Path: tgt})

		case "DconfPolicy":
			var p dc.Policy
			if err := yaml.Unmarshal(b, &p); err != nil {
				r.log.Warn("yaml", err.Error(), "file", path)
				return nil
			}
			sel := selector.Sel{
				Facts:         p.Selector.Facts,
				Tags:          p.Selector.Tags,
				HostnameRegex: p.Selector.HostnameRegex,
			}
			if !sel.Match(selector.Context{Facts: r.lastFacts, Tags: r.lastTags}) {
				return nil
			}
			settings, locks, _, _, err := dc.Render(&p)
			if err != nil {
				r.log.Warn("render", err.Error(), "file", path)
				return nil
			}
			sp, lp := dc.TargetPaths(p.Metadata.Name)
			toApply = append(toApply,
				applyItem{Path: sp, Data: settings, Mode: 0o644},
				applyItem{Path: lp, Data: locks, Mode: 0o644},
			)
			desiredPaths[sp] = struct{}{}
			desiredPaths[lp] = struct{}{}
			desiredManaged = append(desiredManaged, managedItem{Path: sp}, managedItem{Path: lp})
			// We want to recompile the dconf DB whenever any dconf policy is selected or removed.
			dconfTouched = true

		case "ModprobePolicy":
			var p mp.Policy
			if err := yaml.Unmarshal(b, &p); err != nil {
				r.log.Warn("yaml", err.Error(), "file", path)
				return nil
			}
			sel := selector.Sel{
				Facts:         p.Selector.Facts,
				Tags:          p.Selector.Tags,
				HostnameRegex: p.Selector.HostnameRegex,
			}
			if !sel.Match(selector.Context{Facts: r.lastFacts, Tags: r.lastTags}) {
				return nil
			}
			conf, _, err := mp.Render(&p)
			if err != nil {
				r.log.Warn("render", err.Error(), "file", path)
				return nil
			}
			tgt := mp.TargetPath(p.Metadata.Name)
			toApply = append(toApply, applyItem{Path: tgt, Data: conf, Mode: 0o644})
			desiredPaths[tgt] = struct{}{}
			desiredManaged = append(desiredManaged, managedItem{Path: tgt})
			if p.Spec.UpdateInitramfs {
				initramfsTouched = true
			}

		default:
			// ignore unknown kinds
		}
		return nil
	})

	prev := r.loadManaged()
	removed := 0

	for _, it := range prev.Items {
		// only delete files we own and ONLY under our allowlist
		path := it.Path
		if _, stillDesired := desiredPaths[path]; stillDesired {
			continue
		}
		allowed := strings.HasPrefix(path, "/etc/polkit-1/rules.d/60-lgpo-") ||
			strings.HasPrefix(path, "/etc/dconf/db/local.d/60-lgpo-") ||
			strings.HasPrefix(path, "/etc/dconf/db/local.d/locks/60-lgpo-") ||
			strings.HasPrefix(path, "/etc/modprobe.d/60-lgpo-")
		if !allowed {
			continue
		}
		// drift-safe: only remove if file actually exists
		if _, err := os.Stat(path); err == nil {
			if dry {
				removed++
			} else {
				_ = os.Remove(path)
				removed++
				if strings.HasPrefix(path, "/etc/dconf/db/local.d/") {
					dconfTouched = true
				}
				if strings.HasPrefix(path, "/etc/modprobe.d/") {
					initramfsTouched = true
				}
			}
		}
	}

	// Apply changes
	changed := 0
	for _, it := range toApply {
		c, err := r.applyAtomic(it, dry)
		if err != nil {
			r.log.Error("apply", err.Error(), "path", it.Path)
			continue
		}
		if c {
			changed++
		}
	}

	// Post-steps

	if !dry && initramfsTouched {
		_ = exec.CommandContext(ctx, "update-initramfs", "-u").Run()
	}
	if !dry {
		r.saveManaged(desiredManaged)
	}


	if !dry && dconfTouched {
    	if err := ensureDconfProfile(); err != nil {
        	r.log.Warn("dconf", "ensure profile failed", "err", err.Error())
    	}
    	// try compile first for clearer errors
   		if err := exec.CommandContext(ctx, "/usr/bin/dconf", "compile", "/tmp/local.dconf", "/etc/dconf/db/local.d").Run(); err != nil {
        	r.log.Warn("dconf", "compile failed", "err", err.Error())
    	}
    	// then update the system db
    	cmd := exec.CommandContext(ctx, "/usr/bin/dconf", "update")
    	out, err := cmd.CombinedOutput()
    	if err != nil {
        	r.log.Warn("dconf", "update failed", "err", err.Error(), "out", strings.TrimSpace(string(out)))
    	} else {
        	r.log.Info("dconf", "updated system database")
    	}
	}

	// Status + audit
	st := status.Status{
		LastApply: time.Now().UTC().Format(time.RFC3339),
		Result:    "ok",
		Changed:   changed,
		Failed:    0,
		Commit:    commit,
	}
	_ = status.Write(r.cfg.StatusFile, st)

	rec := map[string]any{
		"ts":         time.Now().UTC().Format(time.RFC3339),
		"trigger":    trigger,
		"repo":       r.cfg.Repo,
		"commit":     commit,
		"facts":      r.lastFacts,
		"tags":       r.lastTags,
		"changed":    changed,
		"dryRun":     dry,
		"durationMs": time.Since(start).Milliseconds(),
		"removed":    removed,
	}
	if f, err := os.OpenFile(r.cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		_ = json.NewEncoder(f).Encode(rec)
		_ = f.Close()
	}

	return nil
}

type applyItem struct {
	Path string
	Data []byte
	Mode fs.FileMode
}

func (r *Runner) applyAtomic(it applyItem, dry bool) (bool, error) {
	// Strict allow-list of writable paths
	okPath := strings.HasPrefix(it.Path, "/etc/polkit-1/rules.d/60-lgpo-") ||
		strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/60-lgpo-") ||
		strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/locks/60-lgpo-") ||
		strings.HasPrefix(it.Path, "/etc/modprobe.d/60-lgpo-")
	if !okPath {
		return false, fmt.Errorf("path not allowed: %s", it.Path)
	}

	// Drift check
	if b, err := os.ReadFile(it.Path); err == nil {
		if string(b) == string(it.Data) {
			return false, nil
		}
	}

	// Dry-run
	if dry {
		return true, nil
	}

	// Atomic write
	if err := os.MkdirAll(filepath.Dir(it.Path), 0o755); err != nil {
		return false, err
	}
	tmp := it.Path + ".lgpo-tmp"
	if err := os.WriteFile(tmp, it.Data, 0o600); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, it.Mode); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, it.Path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// ensureDconfProfile guarantees that the system dconf database ("local")
// is included in the user profile so system defaults/locks take effect.
func ensureDconfProfile() error {
	const path = "/etc/dconf/profile/user"
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	content := []byte("user-db:user\nsystem-db:local\n")
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runDconfUpdate finds and runs `dconf update`, logging any failure.
// It tolerates a minimal service PATH and falls back to /usr/bin/dconf if needed.
func runDconfUpdate(ctx context.Context, r *Runner) error {
	bin, err := exec.LookPath("dconf")
	if err != nil {
		// try common absolute path as a fallback
		if _, st := os.Stat("/usr/bin/dconf"); st == nil {
			bin = "/usr/bin/dconf"
		} else {
			return fmt.Errorf("dconf not found in PATH: %v", err)
		}
	}

	cmd := exec.CommandContext(ctx, bin, "update")

	// Ensure we have a sane PATH when running under a minimal service environment.
	if os.Getenv("PATH") == "" {
		cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	} else {
		cmd.Env = os.Environ()
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if len(out) > 0 {
		r.log.Info("dconf", "update output", "out", strings.TrimSpace(string(out)))
	}
	return nil
}

// loadTags reads *.tag files and returns key->value.
// It ignores blank lines and lines starting with '#', and takes the first value line.
func loadTags(dir string) map[string]string {
	m := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return m
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tag") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		val := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			val = line
			break // first non-comment line wins
		}
		k := strings.TrimSuffix(name, ".tag")
		m[k] = val
	}
	return m
}
