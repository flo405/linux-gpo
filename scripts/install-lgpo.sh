#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/lgpo/src"
BIN="/usr/local/bin/lgpod"
SYSTEMD_UNIT="/etc/systemd/system/lgpod.service"
CONFIG="/etc/lgpo/agent.yaml"
TAGS_DIR="/etc/lgpo/tags.d"
CACHE_DIR="/var/lib/lgpo/repo"

# You can override the policies repo at runtime:
POLICY_REPO_URL="${POLICY_REPO_URL:-https://github.com/flo405/linux-gpo.git}"
POLICY_BRANCH="${POLICY_BRANCH:-main}"

echo "[1/7] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  # sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools
else
  echo "Install Git, Go (>=1.20), build tools, dconf-cli, policykit-1, initramfs-tools, then rerun."
  exit 1
fi

echo "[2/7] Laying down source tree..."
sudo rm -rf "$REPO_DIR"
sudo mkdir -p "$REPO_DIR"
sudo chown -R "$(id -u)":"$(id -g)" "$REPO_DIR"
cd "$REPO_DIR"

# ---- BEGIN EMBEDDED SOURCE (created via heredocs) ----
cat > go.mod <<'__LGPO_EOF__'
module github.com/flo405/lgpo

go 1.22

require gopkg.in/yaml.v3 v3.0.1
__LGPO_EOF__

cat > README.md <<'__LGPO_EOF__'
# lgpo (Linux GPO) — MVP

Ultra-simple agent that pulls policies straight from a Git repo and applies
only three safe policy types: **PolkitPolicy**, **DconfPolicy**, **ModprobePolicy**.

*No build/signing pipeline in this MVP.*

## Repo layout (remote source of truth)
`https://github.com/flo405/linux-gpo/` → `policies/` → all `*.yml`

## Build
```bash
go build ./cmd/lgpod
__LGPO_EOF__

