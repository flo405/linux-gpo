package modprobe

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sort"
    "time"
)

func Render(p *Policy) ([]byte, string, error) {
    if err := p.Validate(); err != nil { return nil, "", err }
    var b bytes.Buffer
    fmt.Fprintf(&b, "# Managed by lgpo - %s\n", p.Metadata.Name)
    fmt.Fprintf(&b, "# Generated %s\n\n", time.Now().UTC().Format(time.RFC3339))
    mods := append([]string(nil), p.Spec.Blacklist...)
    sort.Strings(mods)
    for _, m := range mods {
        fmt.Fprintf(&b, "blacklist %s\n", m)
        if p.Spec.InstallFalse {
            fmt.Fprintf(&b, "install %s /bin/false\n", m)
        }
    }
    sum := sha256.Sum256(b.Bytes())
    return b.Bytes(), hex.EncodeToString(sum[:]), nil
}

func TargetPath(name string) string {
    return "/etc/modprobe.d/60-lgpo-" + name + ".conf"
}
