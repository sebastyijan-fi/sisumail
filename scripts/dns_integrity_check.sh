#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

template_only=0
live_required=0
domain="${SISU_DNS_CHECK_DOMAIN:-sisumail.fi}"
user="${SISU_DNS_CHECK_USER:-niklas}"
resolver="${SISU_DNS_CHECK_RESOLVER:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --template-only) template_only=1; shift ;;
    --live-required) live_required=1; shift ;;
    --domain) domain="${2:-}"; shift 2 ;;
    --user) user="${2:-}"; shift 2 ;;
    --resolver) resolver="${2:-}"; shift 2 ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

need_pattern() {
  local pattern="$1" path="$2" label="$3"
  if ! rg -n "$pattern" "$path" >/dev/null; then
    echo "dns-check FAIL: ${label}" >&2
    exit 1
  fi
}

need_pattern 'MX \| `<u>\.sisumail\.fi` \| `10 v6\.<u>\.sisumail\.fi\.`' docs/dns-records.md "tier1 mx template"
need_pattern 'MX \| `<u>\.sisumail\.fi` \| `20 spool\.sisumail\.fi\.`' docs/dns-records.md "tier2 mx template"
need_pattern 'TXT \| `<u>\.sisumail\.fi` \| `v=spf1 -all`' docs/dns-records.md "spf receive-only template"

if [[ $template_only -eq 1 ]]; then
  echo "dns-check OK (template-only)"
  exit 0
fi

if ! command -v dig >/dev/null 2>&1; then
  if [[ $live_required -eq 1 ]]; then
    echo "dns-check FAIL: dig not installed" >&2
    exit 1
  fi
  echo "manual-vector: dig not installed for live dns check"
  exit 3
fi

host="${user}.${domain}"
expect_mx_10="10 v6.${user}.${domain}."
expect_mx_20="20 spool.${domain}."
resolver_arg=()
if [[ -n "${resolver}" ]]; then
  resolver_arg=("@${resolver}")
fi

set +e
mx_out="$(dig "${resolver_arg[@]}" +short MX "${host}" 2>/dev/null)"
mx_rc=$?
txt_out="$(dig "${resolver_arg[@]}" +short TXT "${host}" 2>/dev/null | tr -d '"')"
txt_rc=$?
set -e
if [[ $mx_rc -ne 0 || $txt_rc -ne 0 || -z "${mx_out}" ]]; then
  if [[ $live_required -eq 1 ]]; then
    echo "dns-check FAIL: live dig query failed for ${host}" >&2
    exit 1
  fi
  echo "manual-vector: live dns query unavailable for ${host}"
  exit 3
fi

echo "${mx_out}" | rg -n "^${expect_mx_10}$" >/dev/null || {
  echo "dns-check FAIL: missing expected MX ${expect_mx_10}" >&2
  exit 1
}
echo "${mx_out}" | rg -n "^${expect_mx_20}$" >/dev/null || {
  echo "dns-check FAIL: missing expected MX ${expect_mx_20}" >&2
  exit 1
}
echo "${txt_out}" | rg -n "^v=spf1 -all$" >/dev/null || {
  echo "dns-check FAIL: missing expected SPF v=spf1 -all" >&2
  exit 1
}

echo "dns-check OK (${host})"
