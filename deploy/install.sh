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

  mkdir -p /tmp/sisumail-install
  curl -fsSLo "/tmp/sisumail-install/sisumail.tar.gz" "${url}"
  curl -fsSLo "/tmp/sisumail-install/sha256sum.txt" "${base}/download/${tag}/sha256sum.txt"

  (cd /tmp/sisumail-install && sha256sum -c sha256sum.txt --ignore-missing)

  tar -C /tmp/sisumail-install -xzf /tmp/sisumail-install/sisumail.tar.gz

  install -d -m 0755 "${BIN_DIR}"
  install -m 0755 /tmp/sisumail-install/sisumail-relay "${BIN_DIR}/sisumail-relay"
  install -m 0755 /tmp/sisumail-install/sisumail "${BIN_DIR}/sisumail"
}

install_systemd_units() {
  install -d -m 0755 /etc/systemd/system
  install -m 0644 "$(dirname "$0")/systemd/sisumail-relay.service" /etc/systemd/system/sisumail-relay.service
  install -m 0644 "$(dirname "$0")/systemd/sisumail-update.service" /etc/systemd/system/sisumail-update.service
  install -m 0644 "$(dirname "$0")/systemd/sisumail-update.timer" /etc/systemd/system/sisumail-update.timer

  install -d -m 0755 "${LIB_DIR}"
  install -m 0755 "$(dirname "$0")/vps/update.sh" "${LIB_DIR}/update.sh"

  systemctl daemon-reload
}

ensure_state_dirs() {
  install -d -m 0700 /var/lib/sisumail
  install -d -m 0700 /var/spool/sisumail
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
HCLOUD_TOKEN=
SISUMAIL_DNS_ZONE=
SISUMAIL_IPV6_PREFIX=
EOF
  chmod 0600 "${ENV_FILE}"
  echo "created ${ENV_FILE} (fill it in, then: systemctl restart sisumail-relay)"
}

main() {
  need_root

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
  systemctl enable --now sisumail-update.timer

  echo "installed: ${BIN_DIR}/sisumail-relay"
  echo "next: edit ${ENV_FILE} and restart relay"
}

main "$@"
