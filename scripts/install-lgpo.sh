#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/lgpo/src"
BIN="/usr/local/bin/lgpod"
SYSTEMD_UNIT="/etc/systemd/system/lgpod.service"
CONFIG="/etc/lgpo/agent.yaml"
TAGS_DIR="/etc/lgpo/tags.d"
CACHE_DIR="/var/lib/lgpo/repo"

echo "[1/6] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  # sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools
else
  echo "Please install Git, Go (>=1.20), build tools, dconf-cli, policykit-1, initramfs-tools."
fi

echo "[2/6] Laying down source tree..."
sudo rm -rf "$REPO_DIR"
sudo mkdir -p "$REPO_DIR"
sudo chown -R "$(id -u)":"$(id -g)" "$REPO_DIR"
cd "$REPO_DIR"

echo "[3/6] Building lgpod..."
go mod download
go build ./cmd/lgpod
sudo install -m 0755 ./lgpod "$BIN"

echo "[4/6] Installing systemd unit..."
sudo install -m 0644 packaging/systemd/lgpod.service "$SYSTEMD_UNIT"
sudo systemctl daemon-reload

echo "[5/6] Writing config & directories..."
sudo install -d -m 0755 /etc/lgpo "$TAGS_DIR" /var/lib/lgpo /var/log/lgpo "$CACHE_DIR"
if [ ! -f "$CONFIG" ]; then
  sudo tee "$CONFIG" >/dev/null <<EOF
repo: https://github.com/flo405/linux-gpo.git
branch: main
policiesPath: policies
tagsDir: /etc/lgpo/tags.d
interval: 15m
jitter: 3m
auditLog: /var/log/lgpo/audit.jsonl
statusFile: /var/lib/lgpo/status.json
cacheDir: /var/lib/lgpo/repo
EOF
fi

echo "[6/6] Enabling service..."
sudo systemctl enable --now lgpod || true
echo "Done. Try a dry run: sudo lgpod --sub run --once --dry-run"
