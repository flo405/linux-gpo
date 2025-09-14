package modprobe

import (
    "fmt"
    "regexp"
    "sort"
    "strings"
)

var reName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
var reModule = regexp.MustCompile(`^[a-z0-9]([-_a-z0-9]*[a-z0-9])?$`)

func (p *Policy) Validate() error {
    if p.Kind != "ModprobePolicy" { return fmt.Errorf("kind must be ModprobePolicy") }
    if !reName.MatchString(p.Metadata.Name) { return fmt.Errorf("metadata.name invalid") }
    if len(p.Spec.Blacklist) == 0 { return fmt.Errorf("blacklist empty") }
    norm := make([]string,0,len(p.Spec.Blacklist)*2)
    seen := map[string]bool{}
    for _, m := range p.Spec.Blacklist {
        m = strings.TrimSpace(m)
        if !reModule.MatchString(m) { return fmt.Errorf("bad module %q", m) }
        for _, a := range alts(m) {
            if !seen[a] { seen[a]=true; norm = append(norm, a) }
        }
    }
    sort.Strings(norm)
    p.Spec.Blacklist = norm
    return nil
}
func alts(m string) []string {
    u := strings.ReplaceAll(m, "-", "_")
    h := strings.ReplaceAll(m, "_", "-")
    if u == h { return []string{u} }
    if u < h { return []string{u,h} }
    return []string{h,u}
}
