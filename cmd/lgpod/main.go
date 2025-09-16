package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/lgpo-org/lgpod/pkg/config"
    "github.com/lgpo-org/lgpod/pkg/log"
    "github.com/lgpo-org/lgpod/pkg/run"
)

func main() {
    cfgPath := flag.String("config", "/etc/lgpo/agent.yaml", "config file")
    sub := flag.String("sub", "run", "run|status|facts|tags")
    once := flag.Bool("once", false, "run once then exit")
    dry := flag.Bool("dry-run", false, "plan only")
    flag.Parse()

    l := log.New()

    cfg, err := config.Load(*cfgPath)
    if err != nil { fmt.Fprintln(os.Stderr, "config:", err); os.Exit(1) }
    if err := cfg.EnsureDirs(); err != nil { fmt.Fprintln(os.Stderr, "dirs:", err); os.Exit(1) }

    r := run.New(cfg, l)

    switch *sub {
    case "status":
        s, err := r.ReadStatus()
        if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
        b, _ := json.MarshalIndent(s, "", "  ")
        fmt.Println(string(b))
        return
    case "facts":
        b, _ := json.MarshalIndent(r.Facts(), "", "  ")
        fmt.Println(string(b)); return
    case "tags":
        b, _ := json.MarshalIndent(r.Tags(), "", "  ")
        fmt.Println(string(b)); return
    case "run":
    default:
        fmt.Fprintln(os.Stderr, "unknown sub:", *sub); os.Exit(1)
    }

    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
    defer cancel()

    if *once {
        if err := r.RunOnce(ctx, *dry, "once"); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
        return
    }

    if err := r.RunOnce(ctx, *dry, "boot"); err != nil { l.Warn("initial run", err.Error()) }
    t := time.NewTimer(cfg.IntervalWithJitter())
    for {
        select {
        case <-ctx.Done():
            return
        case <-t.C:
            _ = r.RunOnce(ctx, *dry, "interval")
            t.Reset(cfg.IntervalWithJitter())
        }
    }
}
