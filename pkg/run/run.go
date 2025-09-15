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

	"github.com/flo405/linux-gpo/pkg/config"
	dc "github.com/flo405/linux-gpo/pkg/dconf"
	"github.com/flo405/linux-gpo/pkg/facts"
	"github.com/flo405/linux-gpo/pkg/git"
	"github.com/flo405/linux-gpo/pkg/inventory"
	lglog "github.com/flo405/linux-gpo/pkg/log"
	mp "github.com/flo405/linux-gpo/pkg/modprobe"
	pk "github.com/flo405/linux-gpo/pkg/polkit"
	"github.com/flo405/linux-gpo/pkg/selector"
	"github.com/flo405/linux-gpo/pkg/status"
)

type managedItem struct {
	Path string `json:"path"`
}
type managedState struct {
	Version int           `json:"version"`
	Items   []managedItem `json:"items"`
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

type Runner struct {
	cfg       *config.Config
	log       *lglog.Logger
	lastFacts map[string]string
	lastTags  map[string]string
}

func New(cfg *config.Config, l *lglog.Logger) *Runner {
	return &Runner{cfg: cfg, log: l}
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
		// optional info log if your logger supports Info; fallback to Warn with a friendly message
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
			dconfTouched = true // will be re-set later if only deletions happen; OK to keep true when anything changes

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
	if !dry && dconfTouched {
		_ = exec.CommandContext(ctx, "dconf", "update").Run()
	}
	if !dry && initramfsTouched {
		_ = exec.CommandContext(ctx, "update-initramfs", "-u").Run()
	}
	if !dry {
		r.saveManaged(desiredManaged)
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
		return false
