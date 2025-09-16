# lgpo — Linux Group Policy Objects, reimagined with GitOps

Windows has **Group Policy Objects (GPOs)**: a centralized way to push policy across fleets.  
Linux, by contrast, is gloriously diverse: different desktops (GNOME, KDE, etc.), different distros, and different configuration systems (polkit, dconf/gsettings, systemd, kernel modules…). That diversity makes “Linux GPOs” inherently harder—there’s no single **Registry**, and many subsystems each speak their own language.

**lgpo** is powered by 
- a **unified YAML-based policy language** that is rendered into native Linux config systems by
- a small, security-first agent (**`lgpod`**) that pulls policies from a Git repo.

This early MVP version focuses three policy kinds:
- **PolkitPolicy** → controls privileged actions (who can do what)  
- **DconfPolicy** → GNOME settings + locks (opinionated desktop security)  
- **ModprobePolicy** → kernel module allow/deny (e.g., block USB mass storage)

## GitOps configuration management for Linux workstations
- 🔐 **Change control:** every edit is a PR with history, reviews, and a merge commit you can audit.  
- 👀 **Four-eyes principle & quality gates:** require approvals via CODEOWNERS, enforce status checks (CI, linters, YAML/schema validators, policy render tests) before merge.  
- 🔁 **Reproducibility:** endpoints apply a specific commit; you can correlate any host’s state with the exact Git SHA.  
- ⚡️🛡️ **Safety & speed:** shallow fetches keep bandwidth tiny; rendering is side-effect-free until the final atomic write.  
- ⏪ **Easy rollback:** `git revert` (or restore a previous commit) → agents reset to that state on the next interval.  
- 🧱 **Smaller attack surface:** agents pull over HTTPS directly from Git; fewer privileged services and credentials to defend.
---

## Table of contents

- [Architecture](#architecture)
- [Quick start (PoC)](#quick-start-poc)
- [Policies: examples](#policies-examples)
  - [Block USB storage (Linux kernel)](#block-usb-storage-linux-kernel)
  - [Snap admin only (Ubuntu)](#snap-admin-only-ubuntu)
  - [GNOME lockscreen baseline](#gnome-lockscreen-baseline)
- [Facts & tags (targeting)](#facts--tags-targeting)
- [Interval & jitter (scheduling)](#interval--jitter-scheduling)
- [CLI you’ll use a lot](#cli-youll-use-a-lot)
- [What gets written on disk](#what-gets-written-on-disk)
- [Drift cleanup](#drift-cleanup)
- [Config file](#config-file)
- [How Git sync works](#how-git-sync-works)
- [Roadmap (post-MVP)](#roadmap-postmvp)

---

## Architecture

**GitOps flow**

1. **Policies and inventory lives in Git** (e.g. `https://github.com/lgpo-org/lgpo-gitops-example`).
2. **Agent (`lgpod`) runs on endpoints** on a timer with jitter.
3. Each run:
   - **Shallow-fetches** the branch tip (no history).
   - Discovers **facts** and reads **tags**, evaluates **selectors**.
   - **Renders** matching policies → system files (polkit/dconf/modprobe).
   - **Atomic writes** + **post-steps** (`dconf update`, `update-initramfs -u`).
   - Updates **status** + **audit**; saves a **managed manifest** for cleanup.

**Writable paths (allowlist)**

- `/etc/polkit-1/rules.d/60-lgpo-*.rules`
- `/etc/dconf/db/local.d/60-lgpo-*` and `/etc/dconf/db/local.d/locks/60-lgpo-*`
- `/etc/modprobe.d/60-lgpo-*.conf`

**Drift detection & cleanup**

- The agent tracks previously applied files in `/var/lib/lgpo/managed.json`.  
  On a later run, if a file is **no longer desired** (e.g., device left the `laptops` group), lgpo **deletes** it and triggers the appropriate post-step.

---

## Quick start (PoC)

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/lgpo-org/lgpod/main/scripts/install-lgpo.sh | sudo bash
```

This installs:
- Binary: `/usr/local/bin/lgpod`
- Unit:   `/etc/systemd/system/lgpod.service` (enabled)
- Config: `/etc/lgpo/agent.yaml`
- Cache:  `/var/lib/lgpo/repo`
- State:  `/var/lib/lgpo/status.json`
- Audit:  `/var/log/lgpo/audit.jsonl`

### Put this device in the **laptops** group (tag)

```bash
echo laptops | sudo tee /etc/lgpo/tags.d/group.tag
```

### Dry-run, then apply

```bash
sudo lgpod --sub run --once --dry-run   # preview (no writes)
sudo lgpod --sub run --once             # enforce now (or wait for the service interval)
```

Verify:

```bash
systemctl status lgpod --no-pager
cat /var/lib/lgpo/status.json
tail -n 3 /var/log/lgpo/audit.jsonl
```

---

## Policies: examples

Drop these into your Git repo under `policies/` (any filename ending with `.yml`).

### Block USB storage (Linux kernel)

```yaml
apiVersion: lgpo.io/v1
kind: ModprobePolicy
metadata: { name: block-removable-storage }
selector:
  tags:
    group: ["laptops", "kiosk"]
spec:
  blacklist: ["usb_storage", "uas", "firewire_ohci", "sbp2"]
  installFalse: true       # install <mod> /bin/false → hard-block
  updateInitramfs: true    # rebuild so block applies early
```

**Effect** → `/etc/modprobe.d/60-lgpo-block-removable-storage.conf` + `update-initramfs -u`.

---

### Snap admin only (Ubuntu)

```yaml
apiVersion: lgpo.io/v1
kind: PolkitPolicy
metadata: { name: snap-admin-only }
selector:
  tags:
    group: ["laptops", "workstations"]
spec:
  rules:
    - name: snapd-admin
      matches:
        - action_id: io.snapcraft.snapd.manage
      subject: { group: sudo }          # only sudoers
      result: AUTH_ADMIN_KEEP           # auth once, keep session
      default_result: NO                # everyone else: deny
```

**Effect** → `/etc/polkit-1/rules.d/60-lgpo-snap-admin-only.rules`.

---

### GNOME lockscreen baseline

```yaml
apiVersion: lgpo.io/v1
kind: DconfPolicy
metadata: { name: gnome-security-baseline }
selector:
  tags:
    group: ["laptops"]
spec:
  settings:
    org/gnome/desktop/session:
      idle-delay: "uint32 300"
    org/gnome/desktop/screensaver:
      lock-enabled: "true"
      lock-delay: "uint32 0"
    org/gnome/desktop/media-handling:
      automount: "false"
      automount-open: "false"
    org/gnome/desktop/privacy:
      remember-recent-files: "false"
  locks:
    - /org/gnome/desktop/session/idle-delay
    - /org/gnome/desktop/screensaver/lock-enabled
    - /org/gnome/desktop/screensaver/lock-delay
    - /org/gnome/desktop/media-handling/automount
    - /org/gnome/desktop/media-handling/automount-open
    - /org/gnome/desktop/privacy/remember-recent-files
```

**Effect** →  
`/etc/dconf/db/local.d/60-lgpo-gnome-security-baseline` and  
`/etc/dconf/db/local.d/locks/60-lgpo-gnome-security-baseline`, then `dconf update`.

---

## Facts & tags (targeting)

**facts** (auto-discovered):  
`hostname`, `os.id`, `os.version`, `has_gnome` (true/false), …

**tags** (you control):  
Plain text files in `/etc/lgpo/tags.d/`. The filename (without `.tag`) is the key; the file content is the value.

Examples:

```bash
echo laptops | sudo tee /etc/lgpo/tags.d/group.tag
echo eu      | sudo tee /etc/lgpo/tags.d/geo.tag
```

Use in a policy selector:

```yaml
selector:
  facts:
    has_gnome: "true"
  tags:
    group: ["laptops", "workstations"]
```

---

## Interval & jitter (scheduling)

Config (`/etc/lgpo/agent.yaml`):

```yaml
interval: 15m   # how often to sync/apply
jitter:   3m    # small randomness to avoid herd behavior
```

The agent runs every `interval ± jitter/2`. With the defaults, that’s either **13m30s** or **16m30s** between runs.  
Set `jitter: 0` for deterministic timing; for fleets, 10–20% jitter is a good default.

Restart the service after changing:

```bash
sudo systemctl restart lgpod
```

---

## CLI 

```bash
# Current facts
sudo lgpod --sub facts | jq

# Current tags
sudo lgpod --sub tags  | jq

# Dry-run (no writes)
sudo lgpod --sub run --once --dry-run

# One-shot apply (writes + post-steps)
sudo lgpod --sub run --once

# Status (last apply, changed count, commit)
sudo lgpod --sub status | jq

# Service logs
journalctl -u lgpod -n 50 --no-pager
```

---

## What gets written on disk

- **PolkitPolicy** → `/etc/polkit-1/rules.d/60-lgpo-<name>.rules`  
- **DconfPolicy** → `/etc/dconf/db/local.d/60-lgpo-<name>` and `/etc/dconf/db/local.d/locks/60-lgpo-<name>`  
- **ModprobePolicy** → `/etc/modprobe.d/60-lgpo-<name>.conf`  
- **State** → `/var/lib/lgpo/status.json`  
- **Audit** → `/var/log/lgpo/audit.jsonl`  
- **Managed manifest** → `/var/lib/lgpo/managed.json` (for drift cleanup)

Writes are **atomic** (tmp + rename). Paths outside the allowlist are ignored.

---

## Drift cleanup

If a device stops matching a policy (e.g., you change its `group.tag` from `laptops` to `desktops`), the next run removes previously managed files that are no longer desired. The audit log includes a `removed` count, and `dconf update` / `update-initramfs -u` are triggered when needed.

---

## Config file

`/etc/lgpo/agent.yaml`:

```yaml
repo: https://github.com/lgpo-org/lgpod.git   # Git URL with policies
branch: main                                    # branch name
policiesPath: policies                          # path in repo
tagsDir: /etc/lgpo/tags.d                       # local tags folder
interval: 15m
jitter: 3m
auditLog: /var/log/lgpo/audit.jsonl
statusFile: /var/lib/lgpo/status.json
cacheDir: /var/lib/lgpo/repo
```

---

## How Git sync works

On each run, the agent ensures the cache is at the branch tip:

```bash
# first time
git clone --depth 1 --branch <branch> <repo> <cacheDir>

# updates
git -C <cacheDir> fetch --depth 1 origin <branch>
git -C <cacheDir> reset --hard origin/<branch>
```

This keeps bandwidth minimal (no history) and makes the working tree an exact mirror.  
The commit SHA is recorded in **status** and **audit**.

---

## Roadmap

- Add more policy kinds (e.g. KConfig) 
- SSO/OIDC → tags mapping for identity-aware policies
- Richer facts (inventory, posture signals)  

---

If anything doesn’t behave as described:

```bash
sudo lgpod --sub run --once --dry-run
journalctl -u lgpod -n 100 --no-pager
```

Open an issue with the output and your policy YAML.

