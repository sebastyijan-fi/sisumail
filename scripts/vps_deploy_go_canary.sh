#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage:
  scripts/vps_deploy_go_canary.sh --host <ip-or-hostname> [options]

Options:
  --user <user>                 SSH user (default: root)
  --domain <domain>             discovery domain in well-known payload (default: host)
  --ssh-port <port>             canary SSH listen port (default: 3222)
  --tier1-port <port>           canary Tier 1 proxy port (default: 2625)
  --well-known-port <port>      canary well-known HTTP port (default: 18080)
  --obs-listen <addr>           canary observability listen (default: 127.0.0.1:19090)
  --dev-user <username>         dev routing username (default: niklas)

This script:
  1) builds /tmp/sisumail-relay-go (linux/amd64 static),
  2) uploads binary + well-known JSON,
  3) installs/starts sisumail-relay-go-canary.service on remote host.
EOF
}

host=""
user="root"
domain=""
ssh_port="3222"
tier1_port="2625"
well_known_port="18080"
obs_listen="127.0.0.1:19090"
dev_user="niklas"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) host="${2:-}"; shift 2 ;;
    --user) user="${2:-}"; shift 2 ;;
    --domain) domain="${2:-}"; shift 2 ;;
    --ssh-port) ssh_port="${2:-}"; shift 2 ;;
    --tier1-port) tier1_port="${2:-}"; shift 2 ;;
    --well-known-port) well_known_port="${2:-}"; shift 2 ;;
    --obs-listen) obs_listen="${2:-}"; shift 2 ;;
    --dev-user) dev_user="${2:-}"; shift 2 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$host" ]]; then
  echo "error: --host is required" >&2
  usage
  exit 2
fi

if [[ -z "$domain" ]]; then
  domain="$host"
fi

target="${user}@${host}"
tmp_bin="/tmp/sisumail-relay-go"
tmp_doc="/tmp/sisumail-go-sisu-node.json"
remote_bin="/usr/local/bin/sisumail-relay-go"
remote_doc="/etc/sisumail/sisumail-go-sisu-node.json"
remote_svc="/etc/systemd/system/sisumail-relay-go-canary.service"

if ! command -v go >/dev/null 2>&1; then
  echo "error: go command not found" >&2
  exit 1
fi
if ! command -v ssh >/dev/null 2>&1; then
  echo "error: ssh command not found" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 command not found" >&2
  exit 1
fi

echo "[canary] building relay binary"
export GOMODCACHE="${GOMODCACHE:-/tmp/gomodcache}"
export GOCACHE="${GOCACHE:-/tmp/gocache}"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$tmp_bin" ./cmd/sisumail-relay

node_key_b64="$(python3 - <<'PY'
import os, base64
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"

echo "[canary] generating discovery document"
scripts/generate_well_known_sisu_node.sh \
  --domain "$domain" \
  --node-public-key "$node_key_b64" \
  --ssh-endpoint "${host}:${ssh_port}" \
  --tier1-smtp "<user>.v6.${domain}:${tier1_port}" \
  --tier2-smtp "spool.${domain}:25" \
  --api-endpoint "http://${host}:${well_known_port}" \
  --well-known-url "http://${host}:${well_known_port}/.well-known/sisu-node" \
  --out "$tmp_doc"

echo "[canary] uploading binary"
cat "$tmp_bin" | ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$target" \
  "cat > '$remote_bin' && chmod 0755 '$remote_bin'"

echo "[canary] uploading discovery document"
cat "$tmp_doc" | ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$target" \
  "install -d -m 0755 /etc/sisumail && cat > '$remote_doc' && chown root:sisu '$remote_doc' && chmod 0640 '$remote_doc'"

echo "[canary] installing systemd unit"
ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$target" "bash -s" <<EOF
set -euo pipefail
install -d -m 0750 -o sisu -g sisu /var/lib/sisumail-go /var/spool/sisumail-go /var/spool/sisumail-go/chat
cat > "$remote_svc" <<'UNIT'
[Unit]
Description=Sisumail Relay Go Canary
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sisu
Group=sisu
ExecStart=/usr/local/bin/sisumail-relay-go \
  -ssh-listen :$ssh_port \
  -tier1-listen :$tier1_port \
  -dev-user $dev_user \
  -allow-claim=false \
  -db /var/lib/sisumail-go/relay.db \
  -hostkey /var/lib/sisumail-go/hostkey_ed25519 \
  -spool-dir /var/spool/sisumail-go \
  -chat-spool-dir /var/spool/sisumail-go/chat \
  -obs-listen $obs_listen \
  -well-known-listen :$well_known_port \
  -well-known-path /.well-known/sisu-node \
  -well-known-file $remote_doc
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sisumail-go /var/spool/sisumail-go

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sisumail-relay-go-canary.service
systemctl is-active sisumail-relay-go-canary.service
curl -fsS http://127.0.0.1:$well_known_port/.well-known/sisu-node >/dev/null
EOF

echo "[canary] done target=$target service=sisumail-relay-go-canary"
