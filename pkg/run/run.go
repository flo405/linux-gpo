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

	// 1) Refresh facts
	r.lastFacts = facts.Discover()

	// 2) Update repo cache
	commit, err := git.Ensure(r.cfg.Repo, r.cfg.Branch, r.cfg.CacheDir)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "permission") || strings.Contains(lower, "access") || strings.Contains(lower, "auth") {
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

	// 3) Inventory sync → tags
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
	r.lastTags = loadTags(r.cfg.TagsDir)

	// 4) Evaluate policies
	polDir := filepath.Join(r.cfg.CacheDir, r.cfg.PoliciesDir())

	var toApply []applyItem
	dconfTouched := false
	initramfsTouched := false

	desiredPaths := map[string]struct{}{}
	desiredManaged := make([]managedItem, 0, 64)

	// NEW: instantApply support
	var runtimeModprobe []string
	changedModprobe := false

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
			sel := selector.Sel{Facts: p.Selector.Facts, Tags: p.Selector.Tags, HostnameRegex: p.Selector.HostnameRegex}
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
			sel := selector.Sel{Facts: p.Selector.Facts, Tags: p.Selector.Tags, HostnameRegex: p.Selector.HostnameRegex}
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

		case "ModprobePolicy":
			var p mp.Policy
			if err := yaml.Unmarshal(b, &p); err != nil {
				r.log.Warn("yaml", err.Error(), "file", path)
				return nil
			}
			sel := selector.Sel{Facts: p.Selector.Facts, Tags: p.Selector.Tags, HostnameRegex: p.Selector.HostnameRegex}
			if !sel.Match(selector.Context{Facts: r.lastFacts, Tags: r.lastTags}) {
				return nil
			}
			conf, mods, err := mp.Render(&p)
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
			if p.Spec.InstantApply {
				runtimeModprobe = append(runtimeModprobe, mods...)
			}

		default:
			// ignore unknown kinds
		}
		return nil
	})

	prev := r.loadManaged()
	removed := 0

	for _, it := range prev.Items {
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
					changedModprobe = true
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
			if strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/") ||
				strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/locks/") {
				dconfTouched = true
			}
			if strings.HasPrefix(it.Path, "/etc/modprobe.d/") {
				changedModprobe = true
			}
		}
	}

	// Post-steps: dconf
	if !dry && dconfTouched {
		if err := ensureDconfProfile(); err != nil {
			r.log.Warn("dconf", "ensure profile failed", "err", err.Error())
		}
		// compile local.d for clearer errors first
		if out, err := exec.CommandContext(ctx, "/usr/bin/dconf", "compile", "/tmp/local.dconf", "/etc/dconf/db/local.d").CombinedOutput(); err != nil {
			r.log.Warn("dconf", "compile failed", "err", err.Error(), "out", strings.TrimSpace(string(out)))
		}
		if err := runDconfUpdate(ctx, r); err != nil {
			r.log.Warn("dconf", "update failed", "err", err.Error())
		} else {
			r.log.Info("dconf", "updated system database")
		}
	}

	// Post-steps: initramfs
	if !dry && initramfsTouched {
		_ = exec.CommandContext(ctx, "update-initramfs", "-u").Run()
	}

	// Post-steps: instant modprobe (only if a modprobe file changed)
	if !dry && changedModprobe && len(runtimeModprobe) > 0 {
		uniq := unique(runtimeModprobe)
		if err := runInstantModprobe(ctx, r, uniq); err != nil {
			r.log.Warn("modprobe", "instant apply had errors", "err", err.Error())
		} else {
			r.log.Info("modprobe", "instant apply attempted", "modules", strings.Join(uniq, ","))
		}
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
	okPath := strings.HasPrefix(it.Path, "/etc/polkit-1/rules.d/60-lgpo-") ||
		strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/60-lgpo-") ||
		strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/locks/60-lgpo-") ||
		strings.HasPrefix(it.Path, "/etc/modprobe.d/60-lgpo-")
	if !okPath {
		return false, fmt.Errorf("path not allowed: %s", it.Path)
	}

	if b, err := os.ReadFile(it.Path); err == nil {
		if string(b) == string(it.Data) {
			return false, nil
		}
	}

	if dry {
		return true, nil
	}

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

// ---------- dconf helpers ----------

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

func runDconfUpdate(ctx context.Context, r *Runner) error {
	bin, err := exec.LookPath("dconf")
	if err != nil {
		if _, st := os.Stat("/usr/bin/dconf"); st == nil {
			bin = "/usr/bin/dconf"
		} else {
			return fmt.Errorf("dconf not found in PATH: %v", err)
		}
	}
	cmd := exec.CommandContext(ctx, bin, "update")
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

// ---------- modprobe instant apply ----------

func unique(in []string) []string {
	m := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func runInstantModprobe(ctx context.Context, r *Runner, modules []string) error {
	var firstErr error
	for _, m := range modules {
		if !moduleLoaded(m) {
			continue
		}
		// absolute path; systemd sandboxes may have a minimal PATH
		path := "/sbin/modprobe"
		if _, err := os.Stat(path); err != nil {
			path = "/usr/sbin/modprobe"
		}
		cmd := exec.CommandContext(ctx, path, "-r", m)
		out, err := cmd.CombinedOutput()
		if err != nil {
			r.log.Warn("modprobe", "remove failed", "module", m, "err", err.Error(), "out", strings.TrimSpace(string(out)))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		r.log.Info("modprobe", "removed", "module", m)
	}
	return firstErr
}

func moduleLoaded(name string) bool {
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	s := string(b)
	needle := name + " "
	alt := strings.ReplaceAll(name, "_", "-") + " "
	return strings.Contains(s, needle) || strings.Contains(s, alt)
}

// ---------- tags reader ----------

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
			break
		}
		k := strings.TrimSuffix(name, ".tag")
		m[k] = val
	}
	return m
}
