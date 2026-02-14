#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v govulncheck >/dev/null 2>&1; then
  echo "manual-vector: govulncheck not installed"
  exit 3
fi

govulncheck ./...
echo "vuln-scan OK"
