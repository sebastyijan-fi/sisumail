#!/usr/bin/env bash
set -euo pipefail

host=""
user="root"
iface="eth0"
prefix=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) host="${2:-}"; shift 2 ;;
    --user) user="${2:-}"; shift 2 ;;
    --iface) iface="${2:-}"; shift 2 ;;
    --prefix) prefix="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage:
  scripts/vps_enable_tier1_anyip.sh --host <ip-or-hostname> [--user root] [--iface eth0] [--prefix <ipv6>/64]

What it does (remote):
  - Installs ndppd (NDP proxy) for on-link /64 environments (Hetzner style).
  - Enables sysctls needed for AnyIP + NDP proxy.
  - Installs sisumail-anyip.service to add: ip -6 route local <prefix>/64 dev lo
  - Sets SISUMAIL_TIER1_LISTEN=[::]:25 in /etc/sisumail.env
  - Restarts sisumail-relay

Notes:
  - Tier 2 should bind IPv4 only (0.0.0.0:25) to avoid port conflicts.
  - This does NOT touch OpenSSH port 22.
EOF
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${host}" ]]; then
  echo "error: --host is required" >&2
  exit 2
fi

target="${user}@${host}"
ssh_cmd=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${target}")

remote() {
  "${ssh_cmd[@]}" "$1"
}

if [[ -z "${prefix}" ]]; then
  prefix="$(remote "sed -n 's/^SISUMAIL_IPV6_PREFIX=//p' /etc/sisumail.env 2>/dev/null | head -n1" || true)"
fi
prefix="$(printf '%s' "${prefix}" | tr -d '[:space:]')"
if [[ -z "${prefix}" ]]; then
  echo "error: missing IPv6 prefix. Provide --prefix <ipv6>/64 or set SISUMAIL_IPV6_PREFIX in /etc/sisumail.env" >&2
  exit 1
fi
case "${prefix}" in
  */64) ;;
  *)
    echo "error: expected a /64 prefix (got: ${prefix})" >&2
    exit 1
    ;;
esac

echo "[anyip] target=${target} iface=${iface} prefix=${prefix}"

echo "[anyip] install ndppd"
remote "DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y ndppd >/dev/null"

echo "[anyip] sysctl"
remote "cat > /etc/sysctl.d/99-sisumail-anyip.conf <<'SYS'
net.ipv6.ip_nonlocal_bind=1
net.ipv6.conf.all.proxy_ndp=1
net.ipv6.conf.default.proxy_ndp=1
net.ipv6.conf.${iface}.proxy_ndp=1
SYS
sysctl --system >/dev/null"

echo "[anyip] ndppd config"
remote "cat > /etc/ndppd.conf <<NDP
route-ttl 30000
proxy ${iface} {
  router yes
  timeout 500
  ttl 30000
  rule ${prefix} {
    auto
  }
}
NDP
systemctl enable --now ndppd >/dev/null
systemctl restart ndppd"

echo "[anyip] sisumail-anyip.service"
remote "cat > /etc/systemd/system/sisumail-anyip.service <<'UNIT'
[Unit]
Description=Sisumail AnyIP IPv6 Local Route
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/sisumail.env
ExecStart=/bin/sh -c 'if [ -n \"\${SISUMAIL_IPV6_PREFIX:-}\" ]; then /sbin/ip -6 route replace local \"\$SISUMAIL_IPV6_PREFIX\" dev lo; fi'
ExecStop=/bin/sh -c 'if [ -n \"\${SISUMAIL_IPV6_PREFIX:-}\" ]; then /sbin/ip -6 route del local \"\$SISUMAIL_IPV6_PREFIX\" dev lo 2>/dev/null || true; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sisumail-anyip.service >/dev/null || true"

echo "[anyip] set Tier1 listen to IPv6 :25"
remote "if grep -q '^SISUMAIL_TIER1_LISTEN=' /etc/sisumail.env 2>/dev/null; then
  sed -i 's/^SISUMAIL_TIER1_LISTEN=.*/SISUMAIL_TIER1_LISTEN=[::]:25/' /etc/sisumail.env
else
  printf '\nSISUMAIL_TIER1_LISTEN=[::]:25\n' >> /etc/sisumail.env
fi
chown root:sisu /etc/sisumail.env || true
chmod 0640 /etc/sisumail.env || true"

echo "[anyip] sisumail-relay.service Tier1-ready unit"
remote "cat > /etc/systemd/system/sisumail-relay.service <<'UNIT'
[Unit]
Description=Sisumail Relay (Go)
After=network-online.target
Wants=network-online.target
Wants=sisumail-anyip.service
After=sisumail-anyip.service

[Service]
Type=simple
User=sisu
Group=sisu
EnvironmentFile=/etc/sisumail.env
ExecStart=/bin/sh -c '/usr/local/bin/sisumail-relay \
  -ssh-listen \"\${SISUMAIL_SSH_LISTEN:-:2222}\" \
  -tier1-listen \"\${SISUMAIL_TIER1_LISTEN:-127.0.0.1:2525}\" \
  -allow-claim=\${SISUMAIL_ALLOW_CLAIM:-false} \
  -claim-per-source-per-hour \"\${SISUMAIL_CLAIM_PER_SOURCE_PER_HOUR:-3}\" \
  -claim-per-source-per-day \"\${SISUMAIL_CLAIM_PER_SOURCE_PER_DAY:-12}\" \
  -claim-global-per-hour \"\${SISUMAIL_CLAIM_GLOBAL_PER_HOUR:-200}\" \
  -claim-global-per-day \"\${SISUMAIL_CLAIM_GLOBAL_PER_DAY:-1000}\" \
  -claim-log-retention-days \"\${SISUMAIL_CLAIM_LOG_RETENTION_DAYS:-30}\" \
  -obs-listen \"\${SISUMAIL_OBS_LISTEN:-127.0.0.1:9090}\" \
  -well-known-listen \"\${SISUMAIL_WELL_KNOWN_LISTEN:-}\" \
  -well-known-path \"\${SISUMAIL_WELL_KNOWN_PATH:-/.well-known/sisu-node}\" \
  -well-known-file \"\${SISUMAIL_WELL_KNOWN_FILE:-}\" \
  -tier1-fast-fail-ms \"\${SISUMAIL_TIER1_FAST_FAIL_MS:-200}\" \
  -tier1-open-timeout-ms \"\${SISUMAIL_TIER1_OPEN_TIMEOUT_MS:-3000}\" \
  -tier1-idle-timeout-ms \"\${SISUMAIL_TIER1_IDLE_TIMEOUT_MS:-120000}\" \
  -tier1-max-conn-duration-ms \"\${SISUMAIL_TIER1_MAX_CONN_DURATION_MS:-600000}\" \
  -tier1-max-bytes-per-conn \"\${SISUMAIL_TIER1_MAX_BYTES_PER_CONN:-10485760}\" \
  -tier1-max-conns-per-user \"\${SISUMAIL_TIER1_MAX_CONNS_PER_USER:-10}\" \
  -tier1-max-conns-per-source \"\${SISUMAIL_TIER1_MAX_CONNS_PER_SOURCE:-20}\" \
  -acme-dns01-per-user-per-min \"\${SISUMAIL_ACME_DNS01_PER_USER_PER_MIN:-30}\" \
  -db /var/lib/sisumail/relay.db \
  -hostkey /var/lib/sisumail/hostkey_ed25519 \
  -spool-dir /var/spool/sisumail \
  -chat-spool-dir /var/spool/sisumail/chat'
Restart=always
RestartSec=2

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sisumail /var/spool/sisumail

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload"

echo "[anyip] restart relay"
remote "systemctl restart sisumail-relay"

echo "[anyip] verify listeners"
remote "ss -tulpenHn | sed -n '1,30p'"

echo "[anyip] done"
