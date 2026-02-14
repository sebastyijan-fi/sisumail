#!/usr/bin/env bash
set -euo pipefail

REPO="${SISUMAIL_REPO:-sebastyijan-fi/sisumail}"
VERSION="${SISUMAIL_VERSION:-latest}"
BIN_DIR="${SISUMAIL_BIN_DIR:-$HOME/.local/bin}"

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

resolve_tag() {
  local base="$1"
  if [[ "${VERSION}" != "latest" ]]; then
    echo "${VERSION}"
    return
  fi
  local tag
  tag="$(curl -fsSLI "${base}/latest" | awk -F': ' 'tolower($1)=="location"{print $2}' | tr -d '\r' | sed -n 's#.*/tag/##p')"
  if [[ -z "${tag}" ]]; then
    echo "error: failed to resolve latest release tag" >&2
    exit 1
  fi
  echo "${tag}"
}

verify_checksum() {
  local tmp="$1" fname="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${tmp}" && sha256sum -c sha256sum.txt --ignore-missing | grep -q "${fname}: OK")
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    local want got
    want="$(awk -v f="${fname}" '$2==f{print $1}' "${tmp}/sha256sum.txt")"
    if [[ -z "${want}" ]]; then
      echo "error: checksum entry not found for ${fname}" >&2
      exit 1
    fi
    got="$(shasum -a 256 "${tmp}/${fname}" | awk '{print $1}')"
    if [[ "${want}" != "${got}" ]]; then
      echo "error: checksum mismatch for ${fname}" >&2
      exit 1
    fi
    return
  fi
  echo "error: neither sha256sum nor shasum found; cannot verify release integrity" >&2
  exit 1
}

main() {
  local os arch
  read -r os arch < <(detect_platform)

  local base tag fname tmp
  base="https://github.com/${REPO}/releases"
  tag="$(resolve_tag "${base}")"
  fname="sisumail_${tag}_${os}_${arch}.tar.gz"

  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT

  curl -fsSLo "${tmp}/${fname}" "${base}/download/${tag}/${fname}"
  curl -fsSLo "${tmp}/sha256sum.txt" "${base}/download/${tag}/sha256sum.txt"
  verify_checksum "${tmp}" "${fname}"

  tar -C "${tmp}" -xzf "${tmp}/${fname}"

  install -d -m 0755 "${BIN_DIR}"
  install -m 0755 "${tmp}/sisumail" "${BIN_DIR}/sisumail"

  echo "installed: ${BIN_DIR}/sisumail"
  if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    echo "note: ${BIN_DIR} is not in PATH"
    echo "add this to your shell profile:"
    echo "  export PATH=\"\$PATH:${BIN_DIR}\""
  fi
}

main "$@"
