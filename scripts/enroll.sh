    #!/usr/bin/env bash
    set -euo pipefail
    CONF="/etc/lgpo/agent.yaml"
    TAGS_DIR="/etc/lgpo/tags.d"
    BIN="/usr/local/bin/lgpod"

    sudo install -d -m 0755 /etc/lgpo "$TAGS_DIR" /var/lib/lgpo /var/log/lgpo
    if [ -f ./lgpod ]; then
      sudo install -m 0755 ./lgpod "$BIN"
    fi

    if [ ! -f "$CONF" ]; then
      sudo tee "$CONF" >/dev/null <<'EOF'
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

    echo "Enrollment done. Try:"
    echo "  sudo $BIN --sub run --once --dry-run"
