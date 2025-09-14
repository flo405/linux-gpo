#!/usr/bin/env bash
# set -euo pipefail

# --- Tunables (override via env) ---
SRC_REPO_URL="${SRC_REPO_URL:-https://github.com/flo405/linux-gpo.git}"
SRC_BRANCH="${SRC_BRANCH:-main}"

# Policies come from the same repo/branch by default
POLICY_REPO_URL="${POLICY_REPO_URL:-$SRC_REPO_URL}"
POLICY_BRANCH="${POLICY_BRANCH:-$SRC_BRANCH}"

# Paths
SRC_DIR="${SRC_DIR:-/opt/lgpo/src}"
BIN="${BIN:-/usr/local/bin/lgpod}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-/etc/systemd/system/lgpod.service}"
CONFIG="${CONFIG:-/etc/lgpo/agent.yaml}"
TAGS_DIR="${TAGS_DIR:-/etc/lgpo/tags.d}"
CACHE_DIR="${CACHE_DIR:-/var/lib/lgpo/repo}"

echo "[1/7] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools
else
  echo "This script targets Debian/Ubuntu. Install Git, Go (>=1.20), dconf-cli, policykit-1, initramfs-tools, then rerun."
  exit 1
fi

echo "[2/7] Cloning source from ${SRC_REPO_URL} (branch ${SRC_BRANCH})..."
sudo rm -rf "$SRC_DIR"
sudo mkdir -p "$SRC_DIR"
sudo chown -R "$(id -u)":"$(id -g)" "$SRC_DIR"
git clone --depth 1 --branch "$SRC_BRANCH" "$SRC_REPO_URL" "$SRC_DIR"

echo "[3/7] Normalizing Go module path/imports (if needed)..."
cd "$SRC_DIR"
if grep -q '^module github.com/flo405/lgpo$' go.mod 2>/dev/null; then
  echo " - Rewriting module path to github.com/flo405/linux-gpo"
  go mod edit -module=github.com/flo405/linux-gpo
  echo " - Rewriting imports to github.com/flo405/linux-gpo"
  find . -type f -name '*.go' -print0 | xargs -0 sed -i 's#github.com/flo405/lgpo#github.com/flo405/linux-gpo#g'
fi

echo "[4/7] Building lgpod..."
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"
export GOFLAGS="${GOFLAGS:-}"
export GOFLAGS="${GOFLAGS/-mod=readonly/}"
go env -w GOPROXY="$GOPROXY" >/dev/null 2>&1 || true
go env -w GOSUMDB="$GOSUMDB" >/dev/null 2>&1 || true
GO111MODULE=on go mod tidy
GO111MODULE=on go mod download
go build ./cmd/lgpod
sudo install -m 0755 ./lgpod "$BIN"

echo "[5/7] Installing systemd unit..."
if [ -f "packaging/systemd/lgpod.service" ]; then
  sudo install -m 0644 packaging/systemd/lgpod.service "$SYSTEMD_UNIT"
else
  sudo tee "$SYSTEMD_UNIT" >/dev/null <<'EOF'
[Unit]
Description=lgpo agent (lgpod)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lgpod --sub run --config=/etc/lgpo/agent.yaml
Restart=always
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN CAP_SYS_ADMIN
AmbientCapabilities=
ReadWritePaths=/etc/polkit-1/rules.d /etc/dconf/db/local.d /etc/modprobe.d /var/lib/lgpo /var/log/lgpo
StateDirectory=lgpo
LogsDirectory=lgpo

[Install]
WantedBy=multi-user.target
EOF
fi
sudo systemctl daemon-reload

echo "[6/7] Writing config & prefetching policies..."
sudo install -d -m 0755 /etc/lgpo "$TAGS_DIR" /var/lib/lgpo /var/log/lgpo "$CACHE_DIR"
if [ ! -f "$CONFIG" ]; then
  sudo tee "$CONFIG" >/dev/null <<EOF
repo: ${POLICY_REPO_URL}
branch: ${POLICY_BRANCH}
policiesPath: policies
tagsDir: ${TAGS_DIR}
interval: 15m
jitter: 3m
auditLog: /var/log/lgpo/audit.jsonl
statusFile: /var/lib/lgpo/status.json
cacheDir: ${CACHE_DIR}
EOF
fi
if [ -d "$CACHE_DIR/.git" ]; then
  git -C "$CACHE_DIR" fetch --depth 1 origin "$POLICY_BRANCH"
  git -C "$CACHE_DIR" reset --hard "origin/${POLICY_BRANCH}"
else
  git clone --depth 1 --branch "$POLICY_BRANCH" "$POLICY_REPO_URL" "$CACHE_DIR"
fi
git -C "$CACHE_DIR" rev-parse HEAD || true

echo "[7/7] Enabling service & dry-run..."
sudo systemctl enable --now lgpod || true
sudo "$BIN" --sub run --once --dry-run || true

echo "Done. Try: sudo lgpod --sub status"
