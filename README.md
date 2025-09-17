# lgpo — Linux Group Policy Objects, reimagined with GitOps

Group Policy Objects (GPOs) arrived with Active Directory in February 2000. 25 years later Linux gets an enterprise desktop configuration management system.

In contrast to Windows, Linux is diverse: different distros (Debian, Fedora, etc.) different desktops (GNOME, KDE, etc.), and different configuration systems (polkit, dconf/gsettings, systemd, kernel modules, etc.). That diversity makes “Linux GPOs” inherently harder. There is no single **Registry**, and many subsystems each speak their own language. 

**lgpo** is powered by 
- a **unified YAML-based policy language** that is rendered into different native Linux config systems by
- a small, security-first agent (**`lgpod`**) that pulls policies from a Git repo.

Visit the [GitOps example repo](https://github.com/lgpo-org/lgpo-gitops-example) to learn more about policies and inventory mangement.

## Why GitOps
- 🏛️  Many organizations already trust in GitOps to secure their crown-jewels such as k8s clusters. Use this **well established process** to manage Linux workstations too.
- 👀  With GitOps, it's easy to enforce the **four-eyes principle** and status checks (CI, linters, YAML/schema validators, policy render tests) before merge.  
- 🔐 **Change control:** every edit is a PR with history, reviews, and a merge commit you can audit.  
- 🔁 **Reproducibility:** endpoints apply a specific commit; you can correlate any host’s state with the exact Git SHA.  
- ⏪ **Easy rollback:** `git revert` (or restore a previous commit) → agents reset to that state on the next interval.  
- 🧱 **Smaller attack surface:** agents pull over HTTPS directly from Git; fewer privileged services and credentials to defend.

---

## Quick start (PoC)

### Requirements

Fork the [GitOps example repo](https://github.com/lgpo-org/lgpo-gitops-example) that includes example policy and inventory files. Change the repo visibility to private in Settings / Danger Zone.  

### Install

Copy the command below, change `POLICY_REPO_URL="git@github.com:your-org/your-lgpo-gitops-repo.git"` to your new private repo and run the command.

```bash
curl -fsSL https://raw.githubusercontent.com/lgpo-org/lgpod/main/scripts/install-lgpo.sh \
| sudo env POLICY_REPO_URL="git@github.com:your-org/your-lgpo-gitops-repo.git" POLICY_BRANCH="main" bash
```

### Enrollment
Your device's public key starting with `ssh-ed25519 AAAAC3NzaC1lZD...` and your device id, a hash such as ```7a93be12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90``` will be displayed at the end of the install process.
1. Copy the public key and paste it as a new deploy key (in your GitOps repo's settings, click "deploy keys", grant READ-ONLY access, you can use the hash as name)
2. Copy the hash and paste it into your GitOps repo's devices.yml file in the "inventory" folder to enroll the device.

### Dry-run, then apply

```bash
sudo lgpod --sub run --once --dry-run   # preview (no writes)
sudo lgpod --sub run --once             # enforce now (or wait for the service interval)
```

Verify:

```bash
sudo lgpod -sub tags
sudo lgpod -sub facts
systemctl status lgpod --no-pager
cat /var/lib/lgpo/status.json
tail -n 3 /var/log/lgpo/audit.jsonl
```

---

## Policies: examples

This early MVP version includes three kinds of policies:
- **ModprobePolicy** → kernel module allow/deny (e.g., block USB mass storage)
- **PolkitPolicy** → controls privileged actions (who can do what)  
- **DconfPolicy** → GNOME settings + locks (opinionated desktop security)  

### Block USB storage (ModprobePolicy for most Linux distributions)

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

### Snap admin only (PolkitPolicy for Ubuntu)

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

### Lockscreen baseline (DconfPolicy for GNOME)

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
`hostname`, `os.id`, `os.version`, `has_gnome`, …

**tags** (you control):  
keys such as `group`, `ou`, `team` that contain values defined in your GitOps repo 

Example from the [GitOps example repo](https://github.com/lgpo-org/lgpo-gitops-example/blob/main/inventory/devices.yml):

```yaml
apiVersion: lgpo.io/v1
kind: DeviceInventory
items:
  - device_pub_sha256: "80223685a0606823f104caee502edacd202d7e81ea6f948cd0bff8fb272baafc"
    identity: "alice@example.com"
    tags:
      group: "controlling"
      ou: "finance"
      site: "vienna"
      device: "laptop"
```

Use in a policy selector:

```yaml
selector:
  facts:
    has_gnome: "true"
  tags:
    group: ["developers", "devops"]
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

If a device stops matching a policy (e.g., you change its `group` tag from `laptops` to `desktops`), the next run removes previously managed files that are no longer desired. The audit log includes a `removed` count, and `dconf update` / `update-initramfs -u` are triggered when needed.

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

