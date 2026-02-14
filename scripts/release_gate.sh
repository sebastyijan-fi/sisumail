#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: scripts/release_gate.sh [--with-smoke] [--with-live]

Default:
  - Runs receive-only guardrail checks
  - Runs conformance profile checks
  - Runs go test ./...

Options:
  --with-smoke  Also run local smoke scripts.
  --with-live   Also run live scripts (expects live env/hosts).
  --with-vuln   Also run dependency vulnerability scan (requires govulncheck).
EOF
}

with_smoke=0
with_live=0
with_vuln=0

for arg in "$@"; do
  case "$arg" in
    --with-smoke) with_smoke=1 ;;
    --with-live) with_live=1 ;;
    --with-vuln) with_vuln=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[release-gate] unknown arg: $arg" >&2
      usage
      exit 2
      ;;
  esac
done

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[release-gate] missing required command: $1" >&2
    exit 1
  fi
}

assert_rg() {
  local pattern="$1"
  local path="$2"
  local label="$3"
  if rg -n "$pattern" "$path" >/dev/null; then
    echo "[release-gate] pass: $label"
  else
    echo "[release-gate] FAIL: $label" >&2
    echo "  pattern: $pattern" >&2
    echo "  file:    $path" >&2
    exit 1
  fi
}

need_cmd rg
need_cmd go

echo "[release-gate] P0 receive-only guardrails"
assert_rg "Sisumail is sovereign mail \\*\\*receive\\*\\* infrastructure\\." README.md "README declares receive-only framing"
assert_rg "Sisumail is \\*\\*not\\*\\* an outbound email sending platform\\." README.md "README blocks outbound-email framing"
assert_rg "10 <u>\\.v6\\.sisumail\\.fi\\." docs/dns-records.md "DNS template includes Tier1 MX target"
assert_rg "20 spool\\.sisumail\\.fi\\." docs/dns-records.md "DNS template includes Tier2 MX target"
assert_rg "v=spf1 -all" docs/dns-records.md "DNS template enforces SPF -all"
assert_rg "Sisumail is sovereign receive-only mail infrastructure\\." cmd/sisumail-relay/main.go "hosted shell repeats receive-only framing"
assert_rg "not an outbound email sending platform\\." cmd/sisumail-relay/main.go "hosted shell blocks outbound framing"
assert_rg "X-Sisumail-Tier" cmd/sisumail/main.go "client writes explicit tier headers"
assert_rg "spool reject non-age payload" internal/tier2/spool.go "tier2 spool rejects non-ciphertext payloads"
scripts/artifact_integrity_check.sh
scripts/conformance_check.sh --strict

echo "[release-gate] go test ./..."
go test ./...

if [[ "$with_smoke" == "1" ]]; then
  echo "[release-gate] local smoke scripts"
  scripts/smoke_hosted_shell_local.sh
  scripts/smoke_spool_realtime.sh
  scripts/smoke_spool_on_connect.sh
fi

if [[ "$with_live" == "1" ]]; then
  echo "[release-gate] live smoke scripts"
  scripts/smoke_hosted_shell_live.sh
  scripts/smoke_acme_relay_live.sh
fi

if [[ "$with_vuln" == "1" ]]; then
  echo "[release-gate] dependency vulnerability scan"
  scripts/dependency_vuln_scan.sh
fi

echo "[release-gate] OK"
