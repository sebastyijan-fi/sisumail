#!/usr/bin/env bash
set -euo pipefail

REPO="${SISUMAIL_REPO:-sebastyijan-fi/sisumail}"
VERSION="${SISUMAIL_VERSION:-latest}"
BIN_DIR="${SISUMAIL_BIN_DIR:-/usr/local/bin}"
LIB_DIR="${SISUMAIL_LIB_DIR:-/usr/local/lib/sisumail}"
ENV_FILE="${SISUMAIL_ENV_FILE:-/etc/sisumail.env}"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "error: run as root" >&2
    exit 1
  fi
}

ensure_sisu_user() {
  if id -u sisu >/dev/null 2>&1; then
    return
  fi
  # Dedicated unprivileged service user.
  useradd --system \
    --home-dir /var/lib/sisumail \
    --shell /usr/sbin/nologin \
    --user-group \
    sisu
}

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "error: unsupported arch: ${arch}" >&2; exit 1 ;;
  esac
  case "${os}" in
    linux|darwin) ;;
    *) echo "error: unsupported os: ${os}" >&2; exit 1 ;;
  esac
  echo "${os}" "${arch}"
}

fetch_release() {
  local os="$1" arch="$2"
  local base="https://github.com/${REPO}/releases"
  local tag url
  if [[ "${VERSION}" == "latest" ]]; then
    # Resolve the latest tag name via redirect.
    tag="$(curl -fsSLI "${base}/latest" | awk -F': ' 'tolower($1)=="location"{print $2}' | tr -d '\r' | sed -n 's#.*/tag/##p')"
    if [[ -z "${tag}" ]]; then
      echo "error: failed to resolve latest tag" >&2
      exit 1
    fi
  else
    tag="${VERSION}"
  fi
  url="${base}/download/${tag}/sisumail_${tag}_${os}_${arch}.tar.gz"
  local fname="sisumail_${tag}_${os}_${arch}.tar.gz"

  mkdir -p /tmp/sisumail-install
  curl -fsSLo "/tmp/sisumail-install/${fname}" "${url}"
  curl -fsSLo "/tmp/sisumail-install/sha256sum.txt" "${base}/download/${tag}/sha256sum.txt"

  (cd /tmp/sisumail-install && sha256sum -c sha256sum.txt --ignore-missing | grep -q "${fname}: OK")

  tar -C /tmp/sisumail-install -xzf "/tmp/sisumail-install/${fname}"

  install -d -m 0755 "${BIN_DIR}"
  install -m 0755 /tmp/sisumail-install/sisumail-relay "${BIN_DIR}/sisumail-relay"
  install -m 0755 /tmp/sisumail-install/sisumail-tier2 "${BIN_DIR}/sisumail-tier2"
  install -m 0755 /tmp/sisumail-install/sisumail "${BIN_DIR}/sisumail"
}

install_systemd_units() {
  # NOTE: this script is often executed via curl | bash, so it cannot rely on
  # relative paths next to "$0". Keep installer self-contained.

  install -d -m 0755 /etc/systemd/system
  install -d -m 0755 "${LIB_DIR}"

  cat > /etc/systemd/system/sisumail-anyip.service <<'EOF'
[Unit]
Description=Sisumail AnyIP IPv6 Local Route
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/sisumail.env
ExecStart=/bin/sh -c 'if [ -n "${SISUMAIL_IPV6_PREFIX:-}" ]; then /sbin/ip -6 route replace local "$SISUMAIL_IPV6_PREFIX" dev lo; fi'
ExecStop=/bin/sh -c 'if [ -n "${SISUMAIL_IPV6_PREFIX:-}" ]; then /sbin/ip -6 route del local "$SISUMAIL_IPV6_PREFIX" dev lo 2>/dev/null || true; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/sisumail-relay.service <<'EOF'
[Unit]
Description=Sisumail Relay
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
  -ssh-listen "${SISUMAIL_SSH_LISTEN:-:2222}" \
  -tier1-listen "${SISUMAIL_TIER1_LISTEN:-:2525}" \
  -allow-claim=${SISUMAIL_ALLOW_CLAIM:-false} \
  -claim-per-source-per-hour "${SISUMAIL_CLAIM_PER_SOURCE_PER_HOUR:-3}" \
  -claim-per-source-per-day "${SISUMAIL_CLAIM_PER_SOURCE_PER_DAY:-12}" \
  -claim-global-per-hour "${SISUMAIL_CLAIM_GLOBAL_PER_HOUR:-200}" \
  -claim-global-per-day "${SISUMAIL_CLAIM_GLOBAL_PER_DAY:-1000}" \
  -claim-log-retention-days "${SISUMAIL_CLAIM_LOG_RETENTION_DAYS:-30}" \
  -obs-listen "${SISUMAIL_OBS_LISTEN:-127.0.0.1:9090}" \
  -well-known-listen "${SISUMAIL_WELL_KNOWN_LISTEN:-}" \
  -well-known-path "${SISUMAIL_WELL_KNOWN_PATH:-/.well-known/sisu-node}" \
  -well-known-file "${SISUMAIL_WELL_KNOWN_FILE:-}" \
  -tier1-fast-fail-ms "${SISUMAIL_TIER1_FAST_FAIL_MS:-200}" \
  -tier1-open-timeout-ms "${SISUMAIL_TIER1_OPEN_TIMEOUT_MS:-3000}" \
  -tier1-idle-timeout-ms "${SISUMAIL_TIER1_IDLE_TIMEOUT_MS:-120000}" \
  -tier1-max-conn-duration-ms "${SISUMAIL_TIER1_MAX_CONN_DURATION_MS:-600000}" \
  -tier1-max-bytes-per-conn "${SISUMAIL_TIER1_MAX_BYTES_PER_CONN:-10485760}" \
  -tier1-max-conns-per-user "${SISUMAIL_TIER1_MAX_CONNS_PER_USER:-10}" \
  -tier1-max-conns-per-source "${SISUMAIL_TIER1_MAX_CONNS_PER_SOURCE:-20}" \
  -acme-dns01-per-user-per-min "${SISUMAIL_ACME_DNS01_PER_USER_PER_MIN:-30}" \
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
EOF

  cat > /etc/systemd/system/sisumail-tier2.service <<'EOF'
[Unit]
Description=Sisumail Tier 2 Spool
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sisu
Group=sisu
EnvironmentFile=/etc/sisumail.env
ExecStart=/bin/sh -c '/usr/local/bin/sisumail-tier2 \
  -listen "${SISUMAIL_TIER2_LISTEN:-127.0.0.1:2526}" \
  -zone "$SISUMAIL_DNS_ZONE" \
  -db /var/lib/sisumail/relay.db \
  -spool-dir /var/spool/sisumail \
  -tls-mode "${SISUMAIL_TIER2_TLS_MODE:-opportunistic}" \
  -denylist-path "${SISUMAIL_TIER2_DENYLIST_PATH:-}" \
  -max-conns-per-source "${SISUMAIL_TIER2_MAX_CONNS_PER_SOURCE:-20}" \
  -max-msgs-per-source-per-min "${SISUMAIL_TIER2_MAX_MSGS_PER_SOURCE_PER_MIN:-60}" \
  -tls-cert "${SISUMAIL_TIER2_TLS_CERT:-}" \
  -tls-key "${SISUMAIL_TIER2_TLS_KEY:-}"'
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
EOF

  cat > /etc/systemd/system/sisumail-update.service <<'EOF'
[Unit]
Description=Sisumail Update (pull latest release and restart services)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/sisumail/update.sh
EOF

  cat > /etc/systemd/system/sisumail-update.timer <<'EOF'
[Unit]
Description=Sisumail Update Timer (daily)

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=2h

[Install]
WantedBy=timers.target
EOF

  cat > "${LIB_DIR}/update.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO="${SISUMAIL_REPO:-sebastyijan-fi/sisumail}"
BIN_DIR="${SISUMAIL_BIN_DIR:-/usr/local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "${arch}" in
  x86_64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "unsupported arch: ${arch}" >&2; exit 1 ;;
esac

base="https://github.com/${REPO}/releases"
tag="$(curl -fsSLI "${base}/latest" | awk -F': ' 'tolower($1)=="location"{print $2}' | tr -d '\r' | sed -n 's#.*/tag/##p')"
if [[ -z "${tag}" ]]; then
  echo "failed to resolve latest tag" >&2
  exit 1
fi
fname="sisumail_${tag}_${os}_${arch}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fsSLo "${tmp}/${fname}" "${base}/download/${tag}/${fname}"
curl -fsSLo "${tmp}/sha256sum.txt" "${base}/download/${tag}/sha256sum.txt"
(cd "${tmp}" && sha256sum -c sha256sum.txt --ignore-missing | grep -q "${fname}: OK")

tar -C "${tmp}" -xzf "${tmp}/${fname}"
install -m 0755 "${tmp}/sisumail-relay" "${BIN_DIR}/sisumail-relay"
install -m 0755 "${tmp}/sisumail-tier2" "${BIN_DIR}/sisumail-tier2"
install -m 0755 "${tmp}/sisumail" "${BIN_DIR}/sisumail"

systemctl restart sisumail-relay
systemctl restart sisumail-tier2 || true
EOF

  chmod 0644 /etc/systemd/system/sisumail-relay.service
  chmod 0644 /etc/systemd/system/sisumail-tier2.service
  chmod 0644 /etc/systemd/system/sisumail-anyip.service
  chmod 0644 /etc/systemd/system/sisumail-update.service
  chmod 0644 /etc/systemd/system/sisumail-update.timer
  chmod 0755 "${LIB_DIR}/update.sh"

  systemctl daemon-reload
}

ensure_state_dirs() {
  install -d -m 0700 -o sisu -g sisu /var/lib/sisumail
  install -d -m 0700 -o sisu -g sisu /var/spool/sisumail
  install -d -m 0700 -o sisu -g sisu /var/spool/sisumail/chat
}

ensure_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    return
  fi
  cat > "${ENV_FILE}" <<EOF
# Sisumail relay environment
#
# HCLOUD_TOKEN: Hetzner Console/Cloud API token (Security -> API tokens)
# SISUMAIL_DNS_ZONE: your zone name, e.g. sisumail.fi
# SISUMAIL_IPV6_PREFIX: routed /64 for Tier 1 AnyIP, e.g. 2a01:...::/64
# SISUMAIL_ALLOW_CLAIM: true|false (default false). If true, first-claim is enabled.
# SISUMAIL_TIER1_LISTEN: Tier 1 SMTP blind-proxy listen (staging default :2525, production [::]:25)
# SISUMAIL_SSH_LISTEN: relay SSH gateway listen (default :2222)
# SISUMAIL_TIER2_LISTEN: Tier 2 SMTP bind (staging default 127.0.0.1:2526, production :25)
# SISUMAIL_TIER2_TLS_MODE: disable|opportunistic|required (production: required)
# SISUMAIL_TIER2_TLS_CERT / SISUMAIL_TIER2_TLS_KEY: cert/key for spool.<zone> STARTTLS
# SISUMAIL_TIER2_DENYLIST_PATH: optional file of blocked source IP/CIDR entries
# SISUMAIL_TIER2_MAX_CONNS_PER_SOURCE: per-source concurrent SMTP connection cap
# SISUMAIL_TIER2_MAX_MSGS_PER_SOURCE_PER_MIN: per-source accepted message cap per minute
# SISUMAIL_OBS_LISTEN: local observability endpoint, e.g. 127.0.0.1:9090
# SISUMAIL_WELL_KNOWN_LISTEN: optional public HTTP listener for /.well-known/sisu-node (e.g. :8080)
# SISUMAIL_WELL_KNOWN_PATH: optional discovery path (default /.well-known/sisu-node)
# SISUMAIL_WELL_KNOWN_FILE: JSON file served at discovery path
# SISUMAIL_TIER1_*: Tier 1 hardening controls.
# SISUMAIL_ACME_DNS01_PER_USER_PER_MIN: relay ACME control-channel rate limit
HCLOUD_TOKEN=
SISUMAIL_DNS_ZONE=
SISUMAIL_IPV6_PREFIX=
SISUMAIL_ALLOW_CLAIM=false
SISUMAIL_TIER1_LISTEN=:2525
SISUMAIL_SSH_LISTEN=:2222
SISUMAIL_TIER2_LISTEN=127.0.0.1:2526
SISUMAIL_TIER2_TLS_MODE=opportunistic
SISUMAIL_TIER2_TLS_CERT=
SISUMAIL_TIER2_TLS_KEY=
SISUMAIL_TIER2_DENYLIST_PATH=
SISUMAIL_TIER2_MAX_CONNS_PER_SOURCE=20
SISUMAIL_TIER2_MAX_MSGS_PER_SOURCE_PER_MIN=60
SISUMAIL_OBS_LISTEN=127.0.0.1:9090
SISUMAIL_WELL_KNOWN_LISTEN=
SISUMAIL_WELL_KNOWN_PATH=/.well-known/sisu-node
SISUMAIL_WELL_KNOWN_FILE=
SISUMAIL_TIER1_FAST_FAIL_MS=200
SISUMAIL_TIER1_OPEN_TIMEOUT_MS=3000
SISUMAIL_TIER1_IDLE_TIMEOUT_MS=120000
SISUMAIL_TIER1_MAX_CONN_DURATION_MS=600000
SISUMAIL_TIER1_MAX_BYTES_PER_CONN=10485760
SISUMAIL_TIER1_MAX_CONNS_PER_USER=10
SISUMAIL_TIER1_MAX_CONNS_PER_SOURCE=20
SISUMAIL_ACME_DNS01_PER_USER_PER_MIN=30
EOF
  chown root:sisu "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
  echo "created ${ENV_FILE} (fill it in, then: systemctl restart sisumail-relay)"
}

main() {
  need_root
  ensure_sisu_user

  local os arch
  read -r os arch < <(detect_platform)

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null
    apt-get install -y ca-certificates curl tar >/dev/null
  fi

  ensure_state_dirs
  ensure_env_file

  # Release binaries (best operator UX).
  fetch_release "${os}" "${arch}"

  install_systemd_units

  systemctl enable --now sisumail-relay.service
  systemctl enable --now sisumail-tier2.service
  systemctl enable --now sisumail-anyip.service || true
  systemctl enable --now sisumail-update.timer

  echo "installed: ${BIN_DIR}/sisumail-relay"
  echo "installed: ${BIN_DIR}/sisumail-tier2"
  echo "next: edit ${ENV_FILE} and restart relay"
}

main "$@"
