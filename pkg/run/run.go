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
    "github.com/flo405/linux-gpo/pkg/log"
    gitpkg "github.com/flo405/linux-gpo/pkg/git"
    "github.com/flo405/linux-gpo/pkg/facts"
    "github.com/flo405/linux-gpo/pkg/tags"
    "github.com/flo405/linux-gpo/pkg/selector"
    "github.com/flo405/linux-gpo/pkg/status"

    pk "github.com/flo405/linux-gpo/pkg/polkit"
    mp "github.com/flo405/linux-gpo/pkg/modprobe"
    dc "github.com/flo405/linux-gpo/pkg/dconf"
)

type Runner struct {
    cfg *config.Config
    log *log.Logger
    lastFacts map[string]string
    lastTags  map[string]string
}

func New(cfg *config.Config, l *log.Logger) *Runner {
    return &Runner{cfg: cfg, log: l}
}

func (r *Runner) Facts() map[string]string {
    if r.lastFacts == nil { r.lastFacts = facts.Discover() }
    return r.lastFacts
}
func (r *Runner) Tags() map[string]string {
    if r.lastTags == nil { r.lastTags = tags.Load(r.cfg.TagsDir) }
    return r.lastTags
}

func (r *Runner) ReadStatus() (status.Status, error) {
    return status.Read(r.cfg.StatusFile)
}

func (r *Runner) RunOnce(ctx context.Context, dry bool, trigger string) error {
    start := time.Now()
    r.lastFacts = facts.Discover()
    r.lastTags  = tags.Load(r.cfg.TagsDir)

    commit, err := gitpkg.Ensure(r.cfg.Repo, r.cfg.Branch, r.cfg.CacheDir)
    if err != nil { return err }

    polDir := filepath.Join(r.cfg.CacheDir, r.cfg.PoliciesDir())

    var toApply []applyItem
    var dconfTouched, initramfsTouched bool

    // walk yml
    filepath.WalkDir(polDir, func(path string, d fs.DirEntry, err error) error {
        if err != nil || d.IsDir() { return nil }
        if !strings.HasSuffix(d.Name(), ".yml") { return nil }
        b, err := os.ReadFile(path); if err != nil { r.log.Warn("read", err.Error(), "file", path); return nil }
        // peek kind
        var hdr struct{ Kind string `yaml:"kind"` }
        if err := yaml.Unmarshal(b, &hdr); err != nil { r.log.Warn("yaml", err.Error(), "file", path); return nil }
        switch hdr.Kind {
        case "PolkitPolicy":
            var p pk.Policy; if err := yaml.Unmarshal(b, &p); err != nil { r.log.Warn("yaml", err.Error(), "file", path); return nil }
            if !selector.Sel{Facts:p.Selector.Facts, Tags:p.Selector.Tags, HostnameRegex:p.Selector.HostnameRegex}.Match(selector.Context{Facts:r.lastFacts, Tags:r.lastTags}) { return nil }
            js, _, err := pk.Render(&p); if err != nil { r.log.Warn("render", err.Error(), "file", path); return nil }
            tgt := "/etc/polkit-1/rules.d/60-lgpo-" + p.Metadata.Name + ".rules"
            toApply = append(toApply, applyItem{Path:tgt, Data:js, Mode:0o644})
        case "DconfPolicy":
            var p dc.Policy; if err := yaml.Unmarshal(b, &p); err != nil { r.log.Warn("yaml", err.Error(), "file", path); return nil }
            if !selector.Sel{Facts:p.Selector.Facts, Tags:p.Selector.Tags, HostnameRegex:p.Selector.HostnameRegex}.Match(selector.Context{Facts:r.lastFacts, Tags:r.lastTags}) { return nil }
            s, l, _, _, err := dc.Render(&p); if err != nil { r.log.Warn("render", err.Error(), "file", path); return nil }
            sp, lp := dc.TargetPaths(p.Metadata.Name)
            toApply = append(toApply, applyItem{Path:sp, Data:s, Mode:0o644}, applyItem{Path:lp, Data:l, Mode:0o644})
            dconfTouched = true
        case "ModprobePolicy":
            var p mp.Policy; if err := yaml.Unmarshal(b, &p); err != nil { r.log.Warn("yaml", err.Error(), "file", path); return nil }
            if !selector.Sel{Facts:p.Selector.Facts, Tags:p.Selector.Tags, HostnameRegex:p.Selector.HostnameRegex}.Match(selector.Context{Facts:r.lastFacts, Tags:r.lastTags}) { return nil }
            conf, _, err := mp.Render(&p); if err != nil { r.log.Warn("render", err.Error(), "file", path); return nil }
            tgt := mp.TargetPath(p.Metadata.Name)
            toApply = append(toApply, applyItem{Path:tgt, Data:conf, Mode:0o644})
            if p.Spec.UpdateInitramfs { initramfsTouched = true }
        default:
            // ignore unknown
        }
        return nil
    })

    changed := 0
    for _, it := range toApply {
        c, err := r.applyAtomic(it, dry)
        if err != nil { r.log.Error("apply", err.Error(), "path", it.Path) }
        if c { changed++ }
    }

    // post steps
    if !dry && dconfTouched {
        _ = exec.Command("dconf", "update").Run()
    }
    if !dry && initramfsTouched {
        _ = exec.Command("update-initramfs", "-u").Run()
    }

    // status
    res := "ok"
    s := status.Status{Result:res, Changed:changed, Failed:0, Commit:commit, LastApply: time.Now().UTC().Format(time.RFC3339)}
    _ = status.Write(r.cfg.StatusFile, s)

    // simple audit line
    rec := map[string]any{
        "ts": time.Now().UTC().Format(time.RFC3339),
        "trigger": trigger,
        "repo": r.cfg.Repo,
        "commit": commit,
        "facts": r.lastFacts,
        "tags": r.lastTags,
        "changed": changed,
        "dryRun": dry,
        "durationMs": time.Since(start).Milliseconds(),
    }
    f, _ := os.OpenFile(r.cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
    defer f.Close()
    enc := json.NewEncoder(f); _ = enc.Encode(rec)

    return nil
}

type applyItem struct {
    Path string
    Data []byte
    Mode fs.FileMode
}

func (r *Runner) applyAtomic(it applyItem, dry bool) (bool, error) {
    // allow-list of paths
    if !(strings.HasPrefix(it.Path, "/etc/polkit-1/rules.d/60-lgpo-") ||
         strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/60-lgpo-") ||
         strings.HasPrefix(it.Path, "/etc/dconf/db/local.d/locks/60-lgpo-") ||
         strings.HasPrefix(it.Path, "/etc/modprobe.d/60-lgpo-")) {
        return false, fmt.Errorf("path not allowed: %s", it.Path)
    }
    // check drift
    if b, err := os.ReadFile(it.Path); err == nil {
        if string(b) == string(it.Data) { return false, nil }
    }
    if dry { return true, nil }
    // write atomically
    if err := os.MkdirAll(filepath.Dir(it.Path), 0755); err != nil { return false, err }
    tmp := it.Path + ".lgpo-tmp"
    if err := os.WriteFile(tmp, it.Data, 0o600); err != nil { return false, err }
    if err := os.Chmod(tmp, it.Mode); err != nil { os.Remove(tmp); return false, err }
    if err := os.Rename(tmp, it.Path); err != nil { os.Remove(tmp); return false, err }
    return true, nil
}
