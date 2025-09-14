package tags

import (
    "os"
    "path/filepath"
    "strings"
)

func Load(dir string) map[string]string {
    m := map[string]string{}
    entries, err := os.ReadDir(dir)
    if err != nil { return m }
    for _, e := range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(), ".tag") { continue }
        b, err := os.ReadFile(filepath.Join(dir, e.Name()))
        if err == nil {
            k := strings.TrimSuffix(e.Name(), ".tag")
            m[k] = strings.TrimSpace(string(b))
        }
    }
    return m
}
