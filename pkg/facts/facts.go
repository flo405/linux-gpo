package facts

import (
    "os"
    "os/exec"
    "strings"
)

func Discover() map[string]string {
    f := map[string]string{}
    h, _ := os.Hostname()
    f["hostname"] = h
    f["os.id"] = osRelease("ID")
    f["os.version"] = osRelease("VERSION_ID")
    if _, err := os.Stat("/usr/bin/gnome-shell"); err == nil {
        f["has_gnome"] = "true"
    } else {
        f["has_gnome"] = "false"
    }
    return f
}

func osRelease(key string) string {
    cmd := exec.Command("bash", "-lc", "source /etc/os-release && echo -n ${"+key+"}")
    out, err := cmd.CombinedOutput()
    if err != nil { return "" }
    return strings.TrimSpace(string(out))
}
