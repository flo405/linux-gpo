// pkg/modprobe/types.go
package modprobe

import (
	"fmt"
	"regexp"
	"strings"
)

type Policy struct {
	APIVersion string  `yaml:"apiVersion"`
	Kind       string  `yaml:"kind"`
	Metadata   Meta    `yaml:"metadata"`
	Selector   Sel     `yaml:"selector"`
	Spec       Spec    `yaml:"spec"`
}

type Meta struct {
	Name string `yaml:"name"`
}

type Sel struct {
	Facts         map[string]string      `yaml:"facts"`
	Tags          map[string]any         `yaml:"tags"`
	HostnameRegex string                 `yaml:"hostnameRegex"`
}

type Spec struct {
	Blacklist       []string `yaml:"blacklist"`
	InstallFalse    bool     `yaml:"installFalse"`
	UpdateInitramfs bool     `yaml:"updateInitramfs"`
	InstantApply    bool     `yaml:"instantApply"` 
}

var (
	// linux module name: keep it simple & safe
	modNameRe = regexp.MustCompile(`^[a-z0-9]([-_a-z0-9]*[a-z0-9])?$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Validate performs strict checks mirrored from your MVP.
func (p *Policy) Validate() error {
	if p.Kind != "ModprobePolicy" {
		return fmt.Errorf("kind must be ModprobePolicy")
	}
	if !nameRe.MatchString(p.Metadata.Name) {
		return fmt.Errorf("invalid metadata.name %q", p.Metadata.Name)
	}
	if len(p.Spec.Blacklist) == 0 {
		return fmt.Errorf("spec.blacklist must be non-empty")
	}
	for _, m := range p.Spec.Blacklist {
		if !modNameRe.MatchString(m) {
			return fmt.Errorf("invalid module name %q", m)
		}
	}
	return nil
}

// TargetPath returns the rendered file path for this policy.
func TargetPath(name string) string {
	return "/etc/modprobe.d/60-lgpo-" + name + ".conf"
}

// normalize takes a module and returns a canonical form (underscores),
// plus its hyphen-alias for redundancy in config rendering.
func normalize(mod string) (canon string, alias string) {
	m := strings.ToLower(mod)
	u := strings.ReplaceAll(m, "-", "_")
	h := strings.ReplaceAll(u, "_", "-")
	return u, h
}
