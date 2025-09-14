package log

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
)

type Logger struct{}

func New() *Logger { return &Logger{} }

func (l *Logger) log(level, msg string, kv ...string) {
    m := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "level": level, "msg": msg}
    for i := 0; i+1 < len(kv); i += 2 {
        m[kv[i]] = kv[i+1]
    }
    b, _ := json.Marshal(m)
    fmt.Fprintln(os.Stdout, string(b))
}
func (l *Logger) Info(msg string, kv ...string) { l.log("info", msg, kv...) }
defWarn := "warn"
func (l *Logger) Warn(msg string, kv ...string) { l.log(defWarn, msg, kv...) }
func (l *Logger) Error(msg string, kv ...string) { l.log("error", msg, kv...) }
