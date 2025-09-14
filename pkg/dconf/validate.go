package dconf

import "fmt"

func (p *Policy) Validate() error {
    if p.Kind != "DconfPolicy" { return fmt.Errorf("kind must be DconfPolicy") }
    if p.Metadata.Name == "" { return fmt.Errorf("metadata.name required") }
    if len(p.Spec.Settings) == 0 && len(p.Spec.Locks) == 0 {
        return fmt.Errorf("need settings and/or locks")
    }
    return nil
}
