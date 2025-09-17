# lgpo — Linux Group Policy Objects, reimagined with GitOps

Windows Group Policy Objects (GPOs) arrived with Active Directory in February 2000. 25 years, later Linux gets an enterprise desktop configuration management system that enables organizations to programmatically enforce compliance across a fleet of Linux workstations. 

In contrast to Windows, Linux is gloriously diverse: different distros (Debian, Fedora, etc.) different desktops (GNOME, KDE, etc.), and different configuration systems (polkit, dconf/gsettings, systemd, kernel modules, etc.). That diversity makes “Linux GPOs” inherently harder. There is no single **Registry**, and many subsystems each speak their own language. 

**lgpo** is powered by 
- a **unified YAML-based policy language** that is rendered into different native Linux config systems by
- a small, security-first agent (**`lgpod`**) that pulls policies from a Git repo.

## Policy as Code

lgopd simply matches tags of your policy objects, such as this example policy that blocks usb storage devices on `laptops` and `kiosk` devices 

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

with tags of inventory objects, such as this example that defines a device in the `laptops` group

```yaml
apiVersion: lgpo.io/v1
kind: DeviceInventory
items:
  - device_pub_sha256: "7a93be12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90"
    identity: "alice@example.com"
    tags:
      group: "laptops"
      ou: "finance"
      site: "vienna"
```

Please visit the [GitOps example repo](https://github.com/lgpo-org/lgpo-gitops-example) to learn more about policies and inventory mangement.

## Why GitOps
- 🏛️  Many organizations already trust in GitOps to secure their crown-jewels such as k8s clusters. Use this **well established process** to manage Linux workstations too.
- 👀  With GitOps, it's easy to enforce the **four-eyes principle** and status checks (CI, linters, YAML/schema validators, policy render tests) before merge.  
- 🔐 **Change control:** every edit is a PR with history, reviews, and a merge commit you can audit.  
- 🔁 **Reproducibility:** endpoints apply a specific commit; you can correlate any host’s state with the exact Git SHA.  
- ⏪ **Easy rollback:** `git revert` (or restore a previous commit) → agents reset to that state on the next interval.  
- 🧱 **Smaller attack surface:** agents pull over HTTPS directly from Git; fewer privileged services and credentials to defend.

---

## Quick start

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

Example devices.yml from the [GitOps example repo](https://github.com/lgpo-org/lgpo-gitops-example/blob/main/inventory/devices.yml):

```yaml
apiVersion: lgpo.io/v1
kind: DeviceInventory
items:
  - device_pub_sha256: "7a93be12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90"
    identity: "alice@example.com"
    tags:
      group: "laptops"
      ou: "finance"
      site: "vienna"
```

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

## Config file

`/etc/lgpo/agent.yaml`:

```yaml
repo: git@github.com:your-org/your-lgpo-gitops-repo.git   # policy and inventory repo
branch: main                                              # branch name
policiesPath: policies                                    # policy path in repo
interval: 5m                                              # how often to sync/apply
jitter: 1m                                                # small randomness to avoid herd behavior
auditLog: /var/log/lgpo/audit.jsonl                       # audit logs path
statusFile: /var/lib/lgpo/status.json                     # status file path
cacheDir: /var/lib/lgpo/repo                              # cached repo path
tagsDir: /etc/lgpo/tags.d                                 # local tags folder
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

