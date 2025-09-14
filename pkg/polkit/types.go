package polkit

type Policy struct {
    APIVersion string     `yaml:"apiVersion"`
    Kind       string     `yaml:"kind"`
    Metadata   Meta       `yaml:"metadata"`
    Selector   Sel        `yaml:"selector"`
    Spec       Spec       `yaml:"spec"`
}
type Meta struct{ Name string `yaml:"name"` }
type Sel struct {
    Facts map[string]string `yaml:"facts"`
    Tags  map[string]any    `yaml:"tags"`
    HostnameRegex string    `yaml:"hostnameRegex"`
}
type Spec struct {
    Rules []Rule `yaml:"rules"`
}
type Rule struct {
    Name string `yaml:"name"`
    Description string `yaml:"description,omitempty"`
    Matches []Match `yaml:"matches"`
    Subject Subject `yaml:"subject"`
    Result  Result  `yaml:"result"`
    DefaultResult *Result `yaml:"default_result,omitempty"`
    UnitPrefix string `yaml:"unit_prefix,omitempty"`
}
type Match struct {
    ActionID string `yaml:"action_id,omitempty"`
    ActionPrefix string `yaml:"action_prefix,omitempty"`
}
type Subject struct {
    Active *bool `yaml:"active,omitempty"`
    Group string `yaml:"group,omitempty"`
    User  string `yaml:"user,omitempty"`
}
type Result string
const (
    YES Result = "YES"
    NO  Result = "NO"
    AUTH_ADMIN Result = "AUTH_ADMIN"
    AUTH_ADMIN_KEEP Result = "AUTH_ADMIN_KEEP"
)
func (r Result) JS() string {
    switch r {
    case YES: return "polkit.Result.YES"
    case NO: return "polkit.Result.NO"
    case AUTH_ADMIN: return "polkit.Result.AUTH_ADMIN"
    case AUTH_ADMIN_KEEP: return "polkit.Result.AUTH_ADMIN_KEEP"
    default: return "polkit.Result.NO"
    }
}
