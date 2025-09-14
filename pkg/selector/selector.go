package selector

import "regexp"

type Context struct {
    Facts map[string]string
    Tags  map[string]string
}

type Sel struct {
    Facts map[string]string `yaml:"facts"`
    Tags  map[string]any    `yaml:"tags"`
    HostnameRegex string    `yaml:"hostnameRegex"`
}

func (s Sel) Match(ctx Context) bool {
    if s.HostnameRegex != "" {
        if !regexp.MustCompile(s.HostnameRegex).MatchString(ctx.Facts["hostname"]) { return false }
    }
    for k, v := range s.Facts {
        if ctx.Facts[k] != v { return false }
    }
    for k, v := range s.Tags {
        switch vv := v.(type) {
        case string:
            if ctx.Tags[k] != vv { return false }
        case []any:
            ok := false
            for _, it := range vv {
                if ss, ok2 := it.(string); ok2 && ctx.Tags[k] == ss { ok = true; break }
            }
            if !ok { return false }
        default:
            return false
        }
    }
    return true
}
