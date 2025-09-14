package polkit

import "regexp"
import "fmt"

var reAction = regexp.MustCompile(`^[a-z0-9._-]+$`)
var reName   = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
var reUser   = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)

func (p *Policy) Validate() error {
    if p.Kind != "PolkitPolicy" { return fmt.Errorf("kind must be PolkitPolicy") }
    if !reName.MatchString(p.Metadata.Name) { return fmt.Errorf("metadata.name invalid") }
    if len(p.Spec.Rules) == 0 { return fmt.Errorf("spec.rules empty") }
    for _, r := range p.Spec.Rules {
        if !reName.MatchString(r.Name) { return fmt.Errorf("rule name invalid") }
        if len(r.Matches) == 0 { return fmt.Errorf("rule matches empty") }
        for _, m := range r.Matches {
            if m.ActionID == "" && m.ActionPrefix == "" { return fmt.Errorf("match needs action_id or action_prefix") }
            if m.ActionID != "" && !reAction.MatchString(m.ActionID) { return fmt.Errorf("bad action_id") }
            if m.ActionPrefix != "" && !reAction.MatchString(m.ActionPrefix) { return fmt.Errorf("bad action_prefix") }
        }
        if r.Subject.Group != "" && !reUser.MatchString(r.Subject.Group) { return fmt.Errorf("bad subject.group") }
        if r.Subject.User != "" && !reUser.MatchString(r.Subject.User) { return fmt.Errorf("bad subject.user") }
    }
    return nil
}
