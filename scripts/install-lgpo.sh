#!/usr/bin/env bash
# set -euo pipefail

# --- Tunables (override via env) ---
SRC_REPO_URL="${SRC_REPO_URL:-https://github.com/flo405/linux-gpo.git}"
SRC_BRANCH="${SRC_BRANCH:-main}"
POLICY_REPO_URL="${POLICY_REPO_URL:-$SRC_REPO_URL}"
POLICY_BRANCH="${POLICY_BRANCH:-$SRC_BRANCH}"

# Paths
SRC_DIR="${SRC_DIR:-/opt/lgpo/src}"
BIN="${BIN:-/usr/local/bin/lgpod}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-/etc/systemd/system/lgpod.service}"
CONFIG_DIR="${CONFIG_DIR:-/etc/lgpo}"
CONFIG="${CONFIG:-$CONFIG_DIR/agent.yaml}"
TAGS_DIR="${TAGS_DIR:-$CONFIG_DIR/tags.d}"
STATE_DIR="${STATE_DIR:-/var/lib/lgpo}"
CACHE_DIR="${CACHE_DIR:-$STATE_DIR/repo}"
LOG_DIR="${LOG_DIR:-/var/log/lgpo}"

# --- Pre-flight ---
umask 027
if [[ ! "$SRC_REPO_URL" =~ ^https:// ]]; then
  echo "ERROR: SRC_REPO_URL must be https://"
  exit 1
fi
if [[ ! "$POLICY_REPO_URL" =~ ^https:// ]]; then
  echo "ERROR: POLICY_REPO_URL must be https://"
  exit 1
fi

echo "[1/8] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools
else
  echo "This script targets Debian/Ubuntu."
  exit 1
fi

echo "[2/8] Create system group for read-only access (optional)..."
if ! getent group lgpo >/dev/null; then
  sudo groupadd --system lgpo
fi

echo "[3/8] Cloning and building from ${SRC_REPO_URL} (branch ${SRC_BRANCH})..."
sudo rm -rf "$SRC_DIR"
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 "$SRC_DIR"
git clone --depth 1 --branch "$SRC_BRANCH" "$SRC_REPO_URL" "$SRC_DIR"
cd "$SRC_DIR"

# Normalize Go env
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"
export GOFLAGS="${GOFLAGS:-}"
export GOFLAGS="${GOFLAGS/-mod=readonly/}"
go env -w GOPROXY="$GOPROXY" >/dev/null 2>&1 || true
go env -w GOSUMDB="$GOSUMDB" >/dev/null 2>&1 || true

GO111MODULE=on go mod tidy
GO111MODULE=on go mod download
go build -o lgpod ./cmd/lgpod
sudo install -o root -g root -m 0755 ./lgpod "$BIN"

echo "[4/8] Installing hardened systemd unit..."
sudo tee "$SYSTEMD_UNIT" >/dev/null <<'EOF'
[Unit]
Description=lgpo agent (lgpod)
Documentation=https://github.com/flo405/linux-gpo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
# Make created files 0600/0700 by default; the agent will chmod policy files to 0644 where required.
UMask=0077
Environment=GIT_CONFIG_GLOBAL=/dev/null
# Ensure state/log dirs exist with safe perms before start
ExecStartPre=/usr/bin/install -d -o root -g lgpo -m 0750 /var/lib/lgpo /var/log/lgpo
# Run the agent
ExecStart=/usr/local/bin/lgpod --sub run --config=/etc/lgpo/agent.yaml
Restart=always
RestartSec=10

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
RestrictSUIDSGID=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
# Allow only what we need to write:
ReadWritePaths=/etc/polkit-1/rules.d /etc/dconf/db/local.d /etc/modprobe.d /var/lib/lgpo /var/log/lgpo
# Networking is required for git fetch
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
# Drop all ambient/capabilities
CapabilityBoundingSet=
AmbientCapabilities=

# Create state/log directories (systemd will manage ownership, but ExecStartPre enforces perms)
StateDirectory=lgpo
LogsDirectory=lgpo

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload

echo "[5/8] Creating config + directories with least privilege..."
# Config root-only
sudo install -d -o root -g root -m 0750 "$CONFIG_DIR"
sudo install -d -o root -g root -m 0750 "$TAGS_DIR"
# State + cache (root:lgpo so group can read; 0750)
sudo install -d -o root -g lgpo -m 0750 "$STATE_DIR"
sudo install -d -o root -g lgpo -m 0700 "$CACHE_DIR"
# Logs root:lgpo 0750
sudo install -d -o root -g lgpo -m 0750 "$LOG_DIR"

# Config file (0600)
if [ ! -f "$CONFIG" ]; then
  sudo tee "$CONFIG" >/dev/null <<EOF
repo: ${POLICY_REPO_URL}
branch: ${POLICY_BRANCH}
policiesPath: policies
tagsDir: ${TAGS_DIR}
interval: 15m
jitter: 3m
auditLog: ${LOG_DIR}/audit.jsonl
statusFile: ${STATE_DIR}/status.json
cacheDir: ${CACHE_DIR}
EOF
  sudo chmod 0600 "$CONFIG"
  sudo chown root:root "$CONFIG"
fi

echo "[6/8] Prefetching policies into secure cache..."
# Make git happy in root context and avoid global config reads
sudo git config --global --add safe.directory "$CACHE_DIR" || true
if [ -d "$CACHE_DIR/.git" ]; then
  sudo git -C "$CACHE_DIR" fetch --depth 1 origin "$POLICY_BRANCH"
  sudo git -C "$CACHE_DIR" reset --hard "origin/${POLICY_BRANCH}"
else
  sudo git clone --depth 1 --branch "$POLICY_BRANCH" "$POLICY_REPO_URL" "$CACHE_DIR"
fi
sudo chown -R root:root "$CACHE_DIR"
sudo chmod 0700 "$CACHE_DIR"
sudo find "$CACHE_DIR" -type d -exec chmod 0700 {} \;
sudo find "$CACHE_DIR" -type f -exec chmod 0600 {} \;
sudo git -C "$CACHE_DIR" rev-parse HEAD || true

echo "[7/8] Enable service and run a dry-run (no writes to system yet)..."
sudo systemctl enable --now lgpod || true
sudo "$BIN" --sub run --once --dry-run || true

echo "[8/8] Tighten default perms of state/log files if present..."
# status.json and audit.jsonl are created by the agent; fix perms if they exist
if [ -f "${STATE_DIR}/status.json" ]; then
  sudo chown root:lgpo "${STATE_DIR}/status.json"
  sudo chmod 0640 "${STATE_DIR}/status.json"
fi
if [ -f "${LOG_DIR}/audit.jsonl" ]; then
  sudo chown root:lgpo "${LOG_DIR}/audit.jsonl"
  sudo chmod 0640 "${LOG_DIR}/audit.jsonl"
fi

echo "Done ✅
- Binary:     $BIN (root:root, 0755)
- Unit:       $SYSTEMD_UNIT (enabled)
- Config:     $CONFIG (0600)
- Tags dir:   $TAGS_DIR (0750)
- State dir:  $STATE_DIR (0750, root:lgpo)
- Cache dir:  $CACHE_DIR (0700)
- Log dir:    $LOG_DIR (0750, root:lgpo)
Tip: add your user to 'lgpo' group to read logs/status: sudo usermod -aG lgpo \$USER"
