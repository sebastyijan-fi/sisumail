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

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fsSLo "${tmp}/sisumail.tar.gz" "${base}/download/${tag}/sisumail_${tag}_${os}_${arch}.tar.gz"
curl -fsSLo "${tmp}/sha256sum.txt" "${base}/download/${tag}/sha256sum.txt"
(cd "${tmp}" && sha256sum -c sha256sum.txt --ignore-missing)

tar -C "${tmp}" -xzf "${tmp}/sisumail.tar.gz"
install -m 0755 "${tmp}/sisumail-relay" "${BIN_DIR}/sisumail-relay"
install -m 0755 "${tmp}/sisumail" "${BIN_DIR}/sisumail"

systemctl restart sisumail-relay

