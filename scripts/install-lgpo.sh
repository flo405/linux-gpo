#!/usr/bin/env bash
# scripts/install-lgpo.sh
# Installs lgpod, writes /etc/lgpo/agent.yaml, creates a single OpenSSH ed25519 keypair,
# and prints BOTH the device ID (hash derived from PRIVATE key) and SSH public key.
# Device ID hashing uses SHA-256 of the RAW Ed25519 public key bytes (matches agent).
# set -euo pipefail

# ===== Root check =====
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

# ===== Tunables (override via sudo env VAR=...) =====
SRC_REPO_URL="${SRC_REPO_URL:-https://github.com/lgpo-org/lgpod.git}"
SRC_BRANCH="${SRC_BRANCH:-main}"

# Private repos: prefer SSH form (git@github.com:ORG/REPO.git)
POLICY_REPO_URL="${POLICY_REPO_URL:-https://github.com/lgpo-org/lgpo-gitops-example.git}"
POLICY_BRANCH="${POLICY_BRANCH:-main}"

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
DEVICE_PUB="${DEVICE_PUB:-$DEVICE_DIR/device.key.pub}"
DEVICE_HASH_FILE="${DEVICE_HASH_FILE:-$DEVICE_DIR/device.pub.sha256}"

# Behavior flags
LGPO_REGEN_KEY="${LGPO_REGEN_KEY:-no}"        # yes => force new keypair
LGPO_FORCE_CONFIG="${LGPO_FORCE_CONFIG:-no}"  # yes => overwrite agent.yaml

# ===== 1) Prereqs =====
echo "[1/8] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates curl openssh-client build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools openssl jq coreutils
else
  echo "This script targets Debian/Ubuntu (apt)." >&2
  exit 1
fi

# ===== 2) Fetch sources & build =====
echo "[2/8] Fetching lgpod sources..."
install -d -m 0755 "$SRC_DIR"
if [ -d "$SRC_DIR/.git" ]; then
  git -C "$SRC_DIR" remote set-url origin "$SRC_REPO_URL" || true
  git -C "$SRC_DIR" fetch --depth 1 origin "$SRC_BRANCH"
  git -C "$SRC_DIR" reset --hard "origin/${SRC_BRANCH}"
else
  git clone --depth 1 --branch "$SRC_BRANCH" "$SRC_REPO_URL" "$SRC_DIR"
fi

echo "[3/8] Building lgpod..."
install -d -m 0755 "$(dirname "$BIN")"
( cd "$SRC_DIR/cmd/lgpod" && go build -trimpath -ldflags="-s -w" -o "$BIN" )
chmod 0755 "$BIN"
chown root:root "$BIN"

# ===== 3) Systemd unit =====
echo "[4/8] Installing systemd unit..."
if [ -f "$SRC_DIR/packaging/systemd/lgpod.service" ]; then
  install -m 0644 "$SRC_DIR/packaging/systemd/lgpod.service" "$SYSTEMD_UNIT"
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
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/etc/polkit-1/rules.d /etc/dconf/db /etc/dconf/db/local.d /etc/modprobe.d /var/lib/lgpo /var/log/lgpo /etc/lgpo
CapabilityBoundingSet=CAP_SYS_MODULE
AmbientCapabilities=CAP_SYS_MODULE
SystemCallFilter=@system-service delete_module
StateDirectory=lgpo
LogsDirectory=lgpo
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
User=root

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload

# ===== 4) Config =====
echo "[5/8] Writing config..."
install -d -m 0750 "$(dirname "$CONFIG")" "$TAGS_DIR" "$STATE_DIR" "$LOG_DIR" "$CACHE_DIR"
if [ ! -f "$CONFIG" ] || [ "$LGPO_FORCE_CONFIG" = "yes" ]; then
  [ -f "$CONFIG" ] && echo "LGPO_FORCE_CONFIG=yes → overwriting $CONFIG"
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

sudo tee /etc/dconf/profile/user >/dev/null <<'EOF'
user-db:user
system-db:local
EOF

# ===== 5) Single keypair (SSH auth + device ID) =====
echo "[6/8] Ensuring device key exists at $DEVICE_KEY ..."
systemctl stop lgpod 2>/dev/null || true  # avoid races

generate_key() {
  umask 0177
  install -d -m 0750 "$DEVICE_DIR"
  ssh-keygen -t ed25519 -a 64 -N "" \
    -C "lgpo-$(hostname)-$(cat /etc/machine-id 2>/dev/null || uuidgen)" \
    -f "$DEVICE_KEY"
  chmod 0600 "$DEVICE_KEY" && chown root:root "$DEVICE_KEY"
  chmod 0640 "$DEVICE_PUB" && chown root:root "$DEVICE_PUB"
}

if [ -f "$DEVICE_KEY" ] && [ "$LGPO_REGEN_KEY" != "yes" ]; then
  echo "Existing device key found (LGPO_REGEN_KEY!=yes) → keeping."
else
  [ -f "$DEVICE_KEY" ] && echo "LGPO_REGEN_KEY=yes → regenerating device key."
  rm -f "$DEVICE_KEY" "$DEVICE_PUB" "$DEVICE_HASH_FILE"
  generate_key
fi

# ===== Compute device ID EXACTLY like the agent (SHA-256 of RAW pubkey bytes) =====
# Derive OpenSSH public from PRIVATE key, extract base64 field, decode to raw bytes, hash it.
pub_line="$(ssh-keygen -y -f "$DEVICE_KEY")"                 # "ssh-ed25519 AAAA.... comment"
pub_b64="$(printf '%s\n' "$pub_line" | awk '{print $2}')"    # base64 blob
DEVICE_HASH="$(
  printf '%s' "$pub_b64" | base64 -d | sha256sum | awk '{print $1}'
)"
printf '%s\n' "$DEVICE_HASH" > "$DEVICE_HASH_FILE"
chmod 0640 "$DEVICE_HASH_FILE" && chown root:root "$DEVICE_HASH_FILE"

# ===== 6) Prefetch policies (best-effort) =====
echo "[7/8] Prefetching policy repo into cache (best-effort)..."
if [ -d "$CACHE_DIR/.git" ]; then
  git -C "$CACHE_DIR" remote set-url origin "$POLICY_REPO_URL" || true
  git -C "$CACHE_DIR" fetch --depth 1 origin "$POLICY_BRANCH" || true
  git -C "$CACHE_DIR" reset --hard "origin/${POLICY_BRANCH}" || true
else
  git clone --depth 1 --branch "$POLICY_BRANCH" "$POLICY_REPO_URL" "$CACHE_DIR" || true
fi

# ===== 7) Enable & dry-run =====
echo "[8/8] Enabling lgpod service & doing a dry-run..."
systemctl enable --now lgpod || true
"$BIN" --sub run --once --config="$CONFIG" || true

# ===== Final output =====
echo
echo "Installation complete."
echo
echo "LGPO device ID (SHA-256 of RAW Ed25519 public key derived from *private* key):"
echo "  $DEVICE_HASH"
echo
echo "LGPO device SSH public key (paste into GitHub → Deploy keys, Read-only):"
echo "  $(cat "$DEVICE_PUB")"
echo
echo "Files:"
echo "  Binary      : $BIN"
echo "  Config      : $CONFIG"
echo "  Private key : $DEVICE_KEY (0600 root:root)"
echo "  Public key  : $DEVICE_PUB (0640 root:root)"
echo "  Hash file   : $DEVICE_HASH_FILE (0640 root:root)"
echo "  Cache dir   : $CACHE_DIR"
echo
echo "Next steps:"
echo "  1) Add the SSH public key above as a READ-ONLY Deploy Key on your GitHub repo."
echo "  2) Put this device ID into inventory/devices.yml as device_pub_sha256."
echo "  3) Commit & push; then run:  sudo lgpod --sub run --once"
echo
echo "Tip: Pipe with env:"
echo "  curl -fsSL https://raw.githubusercontent.com/lgpo-org/lgpod/main/scripts/install-lgpo.sh \\"
echo "  | sudo env POLICY_REPO_URL=\"git@github.com:ORG/REPO.git\" POLICY_BRANCH=\"main\" \\"
echo "           LGPO_REGEN_KEY=yes LGPO_FORCE_CONFIG=yes bash"
