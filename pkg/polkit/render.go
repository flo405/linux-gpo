package polkit

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sort"
    "strings"
)

const header = `polkit.addRule(function(action, subject) {
  function isActive() { return !!subject.active; }
  function inGroup(g) { try { return subject.isInGroup(g); } catch(e) { return false; } }
  function isUser(u)  { try { return subject.user === u; } catch(e) { return false; } }
  function unitStartsWith(prefix) {
    try { if (!action.lookup) return false; var u = action.lookup("unit") || ""; return u.indexOf(prefix) === 0; }
    catch(e) { return false; }
  }
`

const footer = `
  // fallthrough: not handled
});
`

func Render(p *Policy) ([]byte, string, error) {
    if err := p.Validate(); err != nil { return nil, "", err }
    var buf bytes.Buffer
    buf.WriteString(header)

    rules := append([]Rule(nil), p.Spec.Rules...)
    sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })

    for _, r := range rules {
        writeRule(&buf, r)
    }
    buf.WriteString(footer)
    js := buf.String()
    for _, bad := range []string{"eval(", "Function(", "require(", "import("} {
        if strings.Contains(js, bad) { return nil, "", fmt.Errorf("forbidden token in output") }
    }
    sum := sha256.Sum256([]byte(js))
    return []byte(js), hex.EncodeToString(sum[:]), nil
}

func writeRule(buf *bytes.Buffer, r Rule) {
    fmt.Fprintf(buf, "\n  // ---- %s ----\n", jsComment(r.Name))
    for _, m := range r.Matches {
        cond := matchCond(m)
        subj := subjectCond(r.Subject)
        unit := unitCond(r.UnitPrefix)
        fmt.Fprintf(buf, "  if (%s%s%s) return %s;\n", cond, subj, unit, r.Result.JS())
    }
    if r.DefaultResult != nil {
        for _, m := range r.Matches {
            if m.ActionPrefix != "" {
                fmt.Fprintf(buf, "  if (action.id.indexOf(%s) === 0) return %s;\n",
                    jsString(m.ActionPrefix), (*r.DefaultResult).JS())
            }
        }
    }
}

func matchCond(m Match) string {
    if m.ActionID != "" { return "action.id === " + jsString(m.ActionID) }
    return "action.id.indexOf(" + jsString(m.ActionPrefix) + ") === 0"
}
func subjectCond(s Subject) string {
    parts := []string{}
    if s.Active != nil {
        if *s.Active { parts = append(parts, "isActive()") } else { parts = append(parts, "!isActive()") }
    }
    if s.Group != "" { parts = append(parts, "inGroup("+jsString(s.Group)+")") }
    if s.User  != "" { parts = append(parts, "isUser("+jsString(s.User)+")") }
    if len(parts) == 0 { return "" }
    return " && (" + strings.Join(parts, " && ") + ")"
}
func unitCond(prefix string) string {
    if prefix == "" { return "" }
    return " && unitStartsWith(" + jsString(prefix) + ")"
}
func jsString(s string) string {
    var b strings.Builder
    b.WriteByte('"')
    for _, r := range s {
        switch r {
        case '\\': b.WriteString('\\\\')
        case '"': b.WriteString('\\"')
        case '\n': b.WriteString('\\n')
        case '\r': b.WriteString('\\r')
        case '\t': b.WriteString('\\t')
        default:
            if r < 32 || r > 126 { fmt.Fprintf(&b, "\\u%04x", r) } else { b.WriteRune(r) }
        }
    }
    b.WriteByte('"')
    return b.String()
}
func jsComment(s string) string {
    out := make([]rune,0,len(s))
    for _, r := range s {
        if r >= 32 && r <= 126 && r != '*' && r != '/' { out = append(out, r) }
    }
    return string(out)
}
