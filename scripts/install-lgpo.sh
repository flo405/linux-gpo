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

umask 027

# ---- 1) Prereqs -------------------------------------------------------------
echo "[1/8] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools
else
  echo "This installer targets Debian/Ubuntu (apt-get)."; exit 1
fi

# ---- 2) System group --------------------------------------------------------
echo "[2/8] Ensuring system group 'lgpo' exists..."
if ! getent group lgpo >/dev/null; then
  sudo groupadd --system lgpo
fi

# ---- 3) Clone & build -------------------------------------------------------
echo "[3/8] Cloning ${SRC_REPO_URL}@${SRC_BRANCH} and building..."
sudo rm -rf "$SRC_DIR"
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 "$SRC_DIR"
git clone --depth 1 --branch "$SRC_BRANCH" "$SRC_REPO_URL" "$SRC_DIR"
cd "$SRC_DIR"

# Go env (quietly tolerate older Go)
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"
export GOFLAGS="${GOFLAGS:-}"
export GOFLAGS="${GOFLAGS/-mod=readonly/}"
go env -w GOPROXY="$GOPROXY" >/dev/null 2>&1 || true
go env -w GOSUMDB="$GOSUMDB" >/dev/null 2>&1 || true

GO111MODULE=on go mod tidy
GO111MODULE=on go mod download
go build -o lgpod ./cmd/lgpod

# Binary: root:lgpo 0750 (not world-executable)
sudo install -o root -g lgpo -m 0750 ./lgpod "$BIN"

# ---- 4) Hardened systemd unit ----------------------------------------------
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
Group=lgpo
UMask=0077
Environment=GIT_CONFIG_GLOBAL=/dev/null
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/etc/polkit-1/rules.d /etc/dconf/db/local.d /etc/modprobe.d /var/lib/lgpo /var/log/lgpo

# Let systemd create these as root:lgpo with tight modes
StateDirectory=lgpo
StateDirectoryMode=0750
LogsDirectory=lgpo
LogsDirectoryMode=0750

[Install]
WantedBy=multi-user.target
EOF
sudo chmod 0644 "$SYSTEMD_UNIT"
sudo systemctl daemon-reload

# ---- 5) Config & dirs (least privilege) ------------------------------------
echo "[5/8] Creating config and directories..."
sudo install -d -o root -g root -m 0750 "$CONFIG_DIR"
sudo install -d -o root -g root -m 0750 "$TAGS_DIR"
sudo install -d -o root -g lgpo -m 0750 "$STATE_DIR"
sudo install -d -o root -g lgpo -m 0700 "$CACHE_DIR"
sudo install -d -o root -g lgpo -m 0750 "$LOG_DIR"

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

# ---- 6) Prefetch policy repo (shallow, secure perms) ------------------------
echo "[6/8] Prefetching policies to ${CACHE_DIR}..."
if [ -d "$CACHE_DIR/.git" ]; then
  sudo git -C "$CACHE_DIR" fetch --depth 1 origin "$POLICY_BRANCH"
  sudo git -C "$CACHE_DIR" reset --hard "origin/${POLICY_BRANCH}"
else
  sudo git clone --depth 1 --branch "$POLICY_BRANCH" "$POLICY_REPO_URL" "$CACHE_DIR"
fi
sudo chown -R root:root "$CACHE_DIR"
sudo find "$CACHE_DIR" -type d -exec chmod 0700 {} \;
sudo find "$CACHE_DIR" -type f -exec chmod 0600 {} \;
sudo git -C "$CACHE_DIR" rev-parse HEAD || true

# ---- 7) Enable service + one-shot dry run ----------------------------------
echo "[7/8] Enabling service & performing dry run..."
sudo systemctl enable --now lgpod || true
sudo "$BIN" --sub run --once --dry-run || true

# ---- 8) Tighten state/log files (if created) --------------------------------
echo "[8/8] Finalizing file permissions..."
if [ -f "${STATE_DIR}/status.json" ]; then
  sudo chown root:lgpo "${STATE_DIR}/status.json"
  sudo chmod 0640 "${STATE_DIR}/status.json"
fi
if [ -f "${LOG_DIR}/audit.jsonl" ]; then
  sudo chown root:lgpo "${LOG_DIR}/audit.jsonl"
  sudo chmod 0640 "${LOG_DIR}/audit.jsonl"
fi

# final restart
sudo systemctl restart lgpod 

echo "Done ✅
- Binary:     $BIN (root:lgpo, 0750)
- Unit:       $SYSTEMD_UNIT (enabled)
- Config:     $CONFIG (0600, root:root)
- Tags dir:   $TAGS_DIR (0750, root:root)
- State dir:  $STATE_DIR (0750, root:lgpo)
- Cache dir:  $CACHE_DIR (0700, root:root)
- Log dir:    $LOG_DIR (0750, root:lgpo)

Tip: add an admin to the 'lgpo' group to read status/logs:
  sudo usermod -aG lgpo <adminuser>
Run: 
  sudo systemctl status lgpod
  sudo lgpod --sub tags
  sudo lgpod --sub status
  sudo cat /var/lib/lgpo/managed.json
"
