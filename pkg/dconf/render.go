package dconf

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sort"
)

func Render(p *Policy) (settings []byte, locks []byte, sumSettings string, sumLocks string, err error) {
    if err = p.Validate(); err != nil { return }
    var sb bytes.Buffer
    keys := make([]string,0,len(p.Spec.Settings))
    for k := range p.Spec.Settings { keys = append(keys, k) }
    sort.Strings(keys)
    for _, group := range keys {
        fmt.Fprintf(&sb, "[%s]\n", group)
        inner := p.Spec.Settings[group]
        ikeys := make([]string,0,len(inner))
        for k := range inner { ikeys = append(ikeys,k) }
        sort.Strings(ikeys)
        for _, k := range ikeys {
            fmt.Fprintf(&sb, "%s=%s\n", k, inner[k])
        }
        sb.WriteString("\n")
    }
    settings = sb.Bytes()
    ssum := sha256.Sum256(settings)
    sumSettings = hex.EncodeToString(ssum[:])

    var lb bytes.Buffer
    if len(p.Spec.Locks) > 0 {
        for _, l := range p.Spec.Locks {
            fmt.Fprintln(&lb, l)
        }
    }
    locks = lb.Bytes()
    lsum := sha256.Sum256(locks)
    sumLocks = hex.EncodeToString(lsum[:])
    return
}

func TargetPaths(name string) (settingsPath, locksPath string) {
    return "/etc/dconf/db/local.d/60-lgpo-" + name, "/etc/dconf/db/local.d/locks/60-lgpo-" + name
}
