package modprobe

type Policy struct {
    APIVersion string `yaml:"apiVersion"`
    Kind       string `yaml:"kind"`
    Metadata   Meta   `yaml:"metadata"`
    Selector   Sel    `yaml:"selector"`
    Spec       Spec   `yaml:"spec"`
}
type Meta struct{ Name string `yaml:"name"` }
type Sel struct {
    Facts map[string]string `yaml:"facts"`
    Tags  map[string]any    `yaml:"tags"`
    HostnameRegex string    `yaml:"hostnameRegex"`
}
type Spec struct {
    Blacklist []string `yaml:"blacklist"`
    InstallFalse bool  `yaml:"installFalse"`
    UpdateInitramfs bool `yaml:"updateInitramfs"`
}
