#!/usr/bin/env bash
# scripts/install-lgpo.sh
# Installs lgpod, sets up config, generates a single device keypair,
# and prints both the device ID (hash derived from the PRIVATE key) and the SSH public key.
# Supports private GitHub policy repos via SSH deploy keys (read-only).

# set -euo pipefail

# ============================================================
# Root check
# ============================================================
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Please run as root (use sudo)."
  exit 1
fi

# ============================================================
# Tunables (override via env; use `sudo env VAR=... bash` when piping)
# ============================================================
SRC_REPO_URL="${SRC_REPO_URL:-https://github.com/lgpo-org/lgpod.git}"
SRC_BRANCH="${SRC_BRANCH:-main}"

# Your policy repo (public or PRIVATE). For private, prefer SSH form: git@github.com:ORG/REPO.git
POLICY_REPO_URL="${POLICY_REPO_URL:-https://github.com/lgpo-org/lgpo-gitops-example.git}"
POLICY_BRANCH="${POLICY_BRANCH:-main}"

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
DEVICE_PUB="${DEVICE_PUB:-$DEVICE_DIR/device.key.pub}"
DEVICE_HASH_FILE="${DEVICE_HASH_FILE:-$DEVICE_DIR/device.pub.sha256}"

# Behavior flags
LGPO_NONINTERACTIVE="${LGPO_NONINTERACTIVE:-0}"   # reserved
LGPO_REGEN_KEY="${LGPO_REGEN_KEY:-no}"            # yes = force regenerate key even if present
LGPO_FORCE_CONFIG="${LGPO_FORCE_CONFIG:-no}"      # yes = overwrite /etc/lgpo/agent.yaml even if present

# ============================================================
# 1) Prereqs
# ============================================================
echo "[1/8] Installing prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates curl openssh-client build-essential pkg-config golang-go \
    dconf-cli policykit-1 initramfs-tools openssl jq
else
  echo "This script targets Debian/Ubuntu (apt)."
  exit 1
fi

# ============================================================
# 2) Fetch sources & build lgpod
# ============================================================
echo "[2/8] Fetching lgpod sources..."
install -d -m 0755 "$SRC_DIR"
if [ -d "$SRC_DIR/.git" ]; then
  git -C "$SRC_DIR" remote set-url origin "$SRC_REPO_URL" || true
  git -C "$SRC_DIR" fetch --depth 1 origin "$SRC_BRANCH"
  git -C "$SRC_DIR" reset --hard "origin/${SRC_BRANCH}"
else
  git clone --depth 1 --branch "$SRC_BRANCH" "$SRC_REPO_URL" "$SRC_DIR"
fi

echo "[3/8] Building and installing lgpod..."
install -d -m 0755 "$(dirname "$BIN")"
# Build with size optimizations, but keep it simple for portability
(cd "$SRC_DIR/cmd/lgpod" && go build -trimpath -ldflags="-s -w" -o "$BIN")
chmod 0755 "$BIN"
chown root:root "$BIN"
"$BIN" --version || true

# ============================================================
# 3) Systemd unit
# ============================================================
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
# 4) Config (agent.yaml)
# ============================================================
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

# ============================================================
# 5) Device identity: single keypair for BOTH GitHub auth & device ID
#    Device ID is derived from the *PRIVATE* key (public half), same rule as before.
# ============================================================
echo "[6/8] Ensuring device key exists at $DEVICE_KEY ..."
# Stop service during key operations to avoid races
systemctl stop lgpod 2>/dev/null || true

generate_key() {
  umask 0177
  install -d -m 0750 "$DEVICE_DIR"
  # Generate OpenSSH Ed25519 keypair (no passphrase)
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
  generate_key
fi

# Compute device ID (SHA-256 of PKIX/PEM public key DERIVED FROM THE PRIVATE KEY)
tmp_pub="$(mktemp)"
tmp_pem="$(mktemp)"
ssh-keygen -y -f "$DEVICE_KEY" > "$tmp_pub"
ssh-keygen -e -m PKCS8 -f "$tmp_pub" > "$tmp_pem"
DEVICE_HASH="$(sha256sum "$tmp_pem" | awk '{print $1}')"
printf '%s\n' "$DEVICE_HASH" > "$DEVICE_HASH_FILE"
chmod 0640 "$DEVICE_HASH_FILE" && chown root:root "$DEVICE_HASH_FILE"
rm -f "$tmp_pub" "$tmp_pem"

# ============================================================
# 6) Prefetch policies (best-effort; may fail before deploy key enrollment)
# ============================================================
echo "[7/8] Prefetching policy repo into cache (best-effort)..."
if [ -d "$CACHE_DIR/.git" ]; then
  git -C "$CACHE_DIR" remote set-url origin "$POLICY_REPO_URL" || true
  git -C "$CACHE_DIR" fetch --depth 1 origin "$POLICY_BRANCH" || true
  git -C "$CACHE_DIR" reset --hard "origin/${POLICY_BRANCH}" || true
else
  git clone --depth 1 --branch "$POLICY_BRANCH" "$POLICY_REPO_URL" "$CACHE_DIR" || true
fi

# ============================================================
# 7) Enable service & dry-run once
# ============================================================
echo "[8/8] Enabling lgpod service & doing a dry-run..."
systemctl enable --now lgpod || true
# First run may fail until deploy key + devices.yml are in place; that's fine.
"$BIN" --sub run --once --config="$CONFIG" || true

# ============================================================
# Final output
# ============================================================
echo
echo "Installation complete."
echo
echo "LGPO device ID (SHA-256 of public key PEM derived from *private* key):"
echo "  $DEVICE_HASH"
echo
echo "LGPO device SSH public key (paste into GitHub → Settings → Deploy keys, Read-only):"
if [ -f "$DEVICE_PUB" ]; then
  echo "  $(cat "$DEVICE_PUB")"
else
  echo "  (missing $DEVICE_PUB)"
fi
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
echo "  1) Add the SSH public key shown above to your GitHub repo as a READ-ONLY Deploy Key."
echo "  2) Put this device ID into your policy repo at inventory/devices.yml as device_pub_sha256."
echo "  3) Commit & push the inventory change."
echo "  4) Run:  sudo lgpod --sub run --once"
echo
echo "Tip: When piping with sudo, pass variables via 'sudo env', e.g.:"
echo "  curl -fsSL https://raw.githubusercontent.com/lgpo-org/lgpod/main/scripts/install-lgpo.sh \\"
echo "  | sudo env POLICY_REPO_URL=\"git@github.com:ORG/REPO.git\" POLICY_BRANCH=\"main\" \\"
echo "           LGPO_REGEN_KEY=yes LGPO_FORCE_CONFIG=yes bash"
