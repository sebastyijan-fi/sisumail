#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

need_pattern() {
  local pattern="$1" path="$2" label="$3"
  if ! rg -n "$pattern" "$path" >/dev/null; then
    echo "artifact-check FAIL: ${label}" >&2
    exit 1
  fi
}

need_pattern "verify_checksum" scripts/install_client.sh "install script has checksum verification function"
need_pattern "verify_checksum \\\"\\$\\{tmp\\}\\\" \\\"\\$\\{fname\\}\\\"" scripts/install_client.sh "install script verifies artifact before install"
need_pattern "error: checksum mismatch" scripts/install_client.sh "install script fails on checksum mismatch"
need_pattern "cannot verify release integrity" scripts/install_client.sh "install script fails closed when checksum tool missing"
need_pattern "sha256sum \"sisumail_\\$\\{VERSION\\}_\"\\*\\.tar\\.gz" scripts/package_release_local.sh "release packaging generates checksum manifest"

# Guard against regression to insecure "skip verification" behavior.
if rg -n "skipping checksum verification" scripts/install_client.sh >/dev/null; then
  echo "artifact-check FAIL: checksum verification skip path detected" >&2
  exit 1
fi

# Basic syntax checks.
bash -n scripts/install_client.sh
bash -n scripts/package_release_local.sh

echo "artifact-check OK"
