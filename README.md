# lgpo (Linux GPO) — MVP

**Ultra-simple** agent that pulls policies straight from a Git repo and applies them on Linux workstations.
There are currently three policy types: **PolkitPolicy**, **DconfPolicy**, **ModprobePolicy**.


## Setup
```bash
curl -fsSL https://raw.githubusercontent.com/flo405/linux-gpo/main/scripts/install-lgpo.sh | sudo bash
```
## Build
```bash
go build ./cmd/lgpod
```

## First run (dry-run)
```bash
sudo ./lgpod --sub run --once --dry-run
```

## Enroll convenience
```bash
sudo ./scripts/enroll.sh
```

## Systemd unit
```bash
sudo cp packaging/systemd/lgpod.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lgpod
```

## Config file
`/etc/lgpo/agent.yaml`
```yaml
repo: https://github.com/flo405/linux-gpo.git
branch: main
policiesPath: policies
tagsDir: /etc/lgpo/tags.d
interval: 15m
jitter: 3m
auditLog: /var/log/lgpo/audit.jsonl
statusFile: /var/lib/lgpo/status.json
cacheDir: /var/lib/lgpo/repo
```

## Example tags
```bash
sudo install -d -m 0755 /etc/lgpo/tags.d
echo laptops | sudo tee /etc/lgpo/tags.d/group.tag
echo eu      | sudo tee /etc/lgpo/tags.d/geo.tag
```

## Policies (examples in `policies/examples/`)
- `*.polkit.yml` → produces `/etc/polkit-1/rules.d/60-lgpo-<name>.rules`
- `*.dconf.yml`  → produces `/etc/dconf/db/local.d/60-lgpo-<name>` and `/etc/dconf/db/local.d/locks/60-lgpo-<name>` then `dconf update`
- `*.modprobe.yml` → produces `/etc/modprobe.d/60-lgpo-<name>.conf` and optionally `update-initramfs -u`
