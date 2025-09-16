#!/usr/bin/env bash
# set -euo pipefail

# ============================================================
# Tunables (override via env)
# ============================================================
SRC_REPO_URL="${SRC_REPO_URL:-https://github.com/lgpo-org/lgpod.git}"
SRC_BRANCH="${SRC_BRANCH:-main}"
POLICY_REPO_URL="${POLICY_REPO_URL:-$SRC_REPO_URL}"
POLICY_BRANCH="${POLICY_BRANCH:-$SRC_BRANCH}"

# Paths
SRC_DIR="${SRC_DIR:-/opt/lgpo/src}"
BIN="${BIN:-/usr/local/bin/lgpod}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-/etc/systemd/system/lgpod.service}"
CONFIG="${CONFIG:-/etc/lgpo/agent.yaml}"
TAGS_DIR="${TAGS_DIR:-/etc/lgpo/tags.d}"
CACHE_DIR="${CACHE_DIR:-/var/lib/lgpo/repo}"
STATE_DIR="${STATE_DIR:-/var/lib/lgpo}"
LOG_DIR="${LOG_DIR:-/var/log/lgpo}"
DEVICE_DIR="${DEVICE_DIR:-/etc/lgpo}"
DEVICE_KEY="${DEVICE_KEY:-$DEVICE_DIR/device.key}"
DEVICE_PUB="${DEVICE_PUB:-$DEVICE_DIR/device.pub}"
DEVICE_HASH_FILE="${DEVICE_HASH_FILE:-$DEVICE_DIR/device.pub.sha256}"

# Behavior flags
LGPO_NONINTERACTIVE="${LGPO_NONINTERACTIVE:-0}"   # set 1 to skip prompts
LGPO_REGEN_KEY="${LGPO_REGEN_KEY:-ask}"           # ask|yes|no (yes=force regen, no=keep existing)

# ============================================================
# Root check
# ============================================================
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Please run as root (use sudo)."
  exit 1
fi

# ============================================================
# 1) Prereqs
# ============================================================
echo "[1/8] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools openssl jq
else
  echo "This script targets Debian/Ubuntu (apt)."
  exit 1
fi

# ============================================================
# 2) Fetch source & build
# ============================================================
echo "[2/8] Cloning source from ${SRC_REPO_URL} (branch ${SRC_BRANCH})..."
rm -rf "$SRC_DIR"
install -d -m 0750 "$SRC_DIR"
chown root:root "$SRC_DIR"
git clone --depth 1 --branch "$SRC_BRANCH" "$SRC_REPO_URL" "$SRC_DIR"
cd "$SRC_DIR"

echo "[3/8] Building lgpod..."
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"
go env -w GOPROXY="$GOPROXY" >/dev/null 2>&1 || true
go env -w GOSUMDB="$GOSUMDB" >/dev/null 2>&1 || true

# Make modules happy, even on first install
GO111MODULE=on go mod tidy
GO111MODULE=on go mod download

go build -o lgpod ./cmd/lgpod
# Least privilege: binary 0750 (root + group can exec). Use group 'sudo' if present, else root.
BIN_GROUP="root"
getent group sudo >/dev/null 2>&1 && BIN_GROUP="sudo"
install -o root -g "$BIN_GROUP" -m 0750 ./lgpod "$BIN"

# ============================================================
# 3) Systemd unit
# ============================================================
echo "[4/8] Installing systemd unit..."
if [ -f "packaging/systemd/lgpod.service" ]; then
  install -m 0644 packaging/systemd/lgpod.service "$SYSTEMD_UNIT"
else
  tee "$SYSTEMD_UNIT" >/dev/null <<'EOF'
[Unit]
Description=lgpo agent (lgpod)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lgpod --sub run --config=/etc/lgpo/agent.yaml
Restart=always
RestartSec=10
# Hardening (paths must be writable via ReadWritePaths)
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
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/etc/polkit-1/rules.d /etc/dconf/db/local.d /etc/modprobe.d /var/lib/lgpo /var/log/lgpo /etc/lgpo
StateDirectory=lgpo
LogsDirectory=lgpo
# Service runs as root (MVP). Consider a dedicated user later.

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload

# ============================================================
# 4) Config & directories (least privilege)
# ============================================================
echo "[5/8] Writing config & creating directories..."
install -d -m 0750 "$(dirname "$CONFIG")" "$TAGS_DIR" "$STATE_DIR" "$LOG_DIR" "$CACHE_DIR"
chown -R root:root /etc/lgpo "$STATE_DIR" "$LOG_DIR" "$CACHE_DIR"
chmod 0750 /etc/lgpo "$TAGS_DIR" "$STATE_DIR" "$CACHE_DIR"
chmod 0750 "$LOG_DIR" || true

if [ ! -f "$CONFIG" ]; then
  tee "$CONFIG" >/dev/null <<EOF
repo: ${POLICY_REPO_URL}
branch: ${POLICY_BRANCH}
policiesPath: policies
tagsDir: ${TAGS_DIR}
interval: 5m
jitter: 1m
auditLog: ${LOG_DIR}/audit.jsonl
statusFile: ${STATE_DIR}/status.json
cacheDir: ${CACHE_DIR}
EOF
  chmod 0640 "$CONFIG"
fi

# Prefetch policies (not required, but nice)
if [ -d "$CACHE_DIR/.git" ]; then
  git -C "$CACHE_DIR" fetch --depth 1 origin "$POLICY_BRANCH" || true
  git -C "$CACHE_DIR" reset --hard "origin/${POLICY_BRANCH}" || true
else
  git clone --depth 1 --branch "$POLICY_BRANCH" "$POLICY_REPO_URL" "$CACHE_DIR" || true
fi

# ============================================================
# 5) Device identity: create /etc/lgpo/device.key (Ed25519), pub, hash
# ============================================================
echo "[6/8] Ensuring device key exists at $DEVICE_KEY ..."
generate_key() {
  umask 0177
  install -d -m 0750 "$DEVICE_DIR"
  # Generate Ed25519 private key
  openssl genpkey -algorithm Ed25519 -out "$DEVICE_KEY"
  chmod 0600 "$DEVICE_KEY"
  chown root:root "$DEVICE_KEY"
  # Extract public key (PEM)
  openssl pkey -in "$DEVICE_KEY" -pubout -out "$DEVICE_PUB"
  chmod 0640 "$DEVICE_PUB"
  chown root:root "$DEVICE_PUB"
}

if [ -f "$DEVICE_KEY" ]; then
  case "$LGPO_REGEN_KEY" in
    yes)
      echo "LGPO_REGEN_KEY=yes → regenerating device key (existing key will be replaced)."
      generate_key
      ;;
    no)
      echo "LGPO_REGEN_KEY=no → keeping existing device key."
      ;;
    *)
      if [ "$LGPO_NONINTERACTIVE" = "1" ]; then
        echo "Non-interactive mode; keeping existing device key."
      else
        echo "A device key already exists at $DEVICE_KEY."
        read -r -p "Keep existing key? [K]eep/[R]egenerate (default: K): " reply || true
        case "${reply:-K}" in
          r|R) generate_key ;;
          *)   echo "Keeping existing key." ;;
        esac
      fi
      ;;
  esac
else
  generate_key
fi

# Compute SHA-256 of public key (PEM) → device ID
DEVICE_HASH="$(openssl pkey -in "$DEVICE_KEY" -pubout -outform PEM | sha256sum | awk '{print $1}')"
printf '%s\n' "$DEVICE_HASH" > "$DEVICE_HASH_FILE"
chmod 0640 "$DEVICE_HASH_FILE"
chown root:root "$DEVICE_HASH_FILE"

# ============================================================
# 6) Enable service & dry-run once
# ============================================================
echo "[7/8] Enabling lgpod service & doing a dry-run..."
systemctl enable --now lgpod || true
"$BIN" --sub run --once --dry-run || true
sudo systemctl restart lgpod
# ============================================================
# 7) Done — print the device hash clearly
# ============================================================
echo "[8/8] Installation complete."
echo
echo "LGPO device ID (SHA-256 of public key PEM):"
echo "  $DEVICE_HASH"
echo
echo "Files:"
echo "  Private key : $DEVICE_KEY (0600 root:root)"
echo "  Public key  : $DEVICE_PUB (0640 root:root)"
echo "  Hash file   : $DEVICE_HASH_FILE (0640 root:root)"
echo
echo "Next steps:"
echo "  1) Add this device ID to your repo's inventory/devices.yml with desired tags."
echo "  2) Run:  sudo lgpod --sub run --once   # to apply policies immediately"
