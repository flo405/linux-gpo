package config

import (
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
    "time"

    "gopkg.in/yaml.v3"
)

type Config struct {
    Repo         string `yaml:"repo"`
    Branch       string `yaml:"branch"`
    PoliciesPath string `yaml:"policiesPath"`
    TagsDir      string `yaml:"tagsDir"`
    IntervalStr  string `yaml:"interval"`
    JitterStr    string `yaml:"jitter"`
    AuditLog     string `yaml:"auditLog"`
    StatusFile   string `yaml:"statusFile"`
    CacheDir     string `yaml:"cacheDir"`
}

func Load(path string) (*Config, error) {
    b, err := ioutil.ReadFile(path)
    if err != nil { return nil, err }
    var c Config
    if err := yaml.Unmarshal(b, &c); err != nil { return nil, err }
    if c.Branch == "" { c.Branch = "main" }
    if c.PoliciesPath == "" { c.PoliciesPath = "policies" }
    if c.TagsDir == "" { c.TagsDir = "/etc/lgpo/tags.d" }
    if c.IntervalStr == "" { c.IntervalStr = "15m" }
    if c.JitterStr == "" { c.JitterStr = "3m" }
    if c.AuditLog == "" { c.AuditLog = "/var/log/lgpo/audit.jsonl" }
    if c.StatusFile == "" { c.StatusFile = "/var/lib/lgpo/status.json" }
    if c.CacheDir == "" { c.CacheDir = "/var/lib/lgpo/repo" }
    return &c, nil
}

func (c *Config) EnsureDirs() error {
    for _, p := range []string{filepath.Dir(c.AuditLog), filepath.Dir(c.StatusFile), c.CacheDir} {
        if err := os.MkdirAll(p, 0755); err != nil { return err }
    }
    return nil
}

func (c *Config) Interval() time.Duration {
    d, _ := time.ParseDuration(c.IntervalStr)
    if d <= 0 { d = 15 * time.Minute }
    return d
}
func (c *Config) Jitter() time.Duration {
    d, _ := time.ParseDuration(c.JitterStr)
    if d < 0 { d = 0 }
    return d
}
func (c *Config) IntervalWithJitter() time.Duration {
    base := c.Interval()
    j := c.Jitter()
    if j == 0 { return base }
    // simple +/- 50% of jitter duration based on time
    n := time.Now().UnixNano()
    s := int64(1)
    if n&1 == 0 { s = -1 }
    return base + time.Duration(s)*j/2
}

func (c *Config) PoliciesDir() string {
    return strings.TrimSuffix(c.PoliciesPath, "/")
}
