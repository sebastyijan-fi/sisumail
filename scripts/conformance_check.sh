#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: scripts/conformance_check.sh [--strict] [--out-dir <dir>] [--profile <name>...]

Profiles:
  core-node
  relay-node
  client

Default:
  - Runs all profiles
  - Writes machine-readable reports to ./conformance

Options:
  --strict    Exit non-zero when any MUST check fails.
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

strict=0
out_dir="conformance"
profiles=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      strict=1
      shift
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --profile)
      profiles+=("${2:-}")
      shift 2
      ;;
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

if [[ ${#profiles[@]} -eq 0 ]]; then
  profiles=("core-node" "relay-node" "client")
fi

need_cmd rg
mkdir -p "$out_dir"

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

declare -A report_file
declare -A first_item
declare -A check_total
declare -A must_total
declare -A must_fail
declare -A na_total
declare -A result_status

start_profile() {
  local profile="$1"
  local path="$out_dir/${profile}.report.json"
  report_file["$profile"]="$path"
  first_item["$profile"]=1
  check_total["$profile"]=0
  must_total["$profile"]=0
  must_fail["$profile"]=0
  na_total["$profile"]=0
  cat > "$path" <<EOF
{
  "profile": "$(json_escape "$profile")",
  "version_target": "sisu-v1",
  "generated_at": "$generated_at",
  "checks": [
EOF
}

append_check() {
  local profile="$1"
  local id="$2"
  local level="$3"
  local status="$4"
  local description="$5"
  local evidence="$6"
  local path="${report_file[$profile]}"

  if [[ "${first_item[$profile]}" == "0" ]]; then
    printf ',\n' >> "$path"
  else
    first_item["$profile"]=0
  fi

  printf '    {"id":"%s","level":"%s","status":"%s","description":"%s","evidence":"%s"}' \
    "$(json_escape "$id")" \
    "$(json_escape "$level")" \
    "$(json_escape "$status")" \
    "$(json_escape "$description")" \
    "$(json_escape "$evidence")" >> "$path"

  check_total["$profile"]=$(( ${check_total["$profile"]} + 1 ))
  if [[ "$level" == "MUST" ]]; then
    if [[ "$status" == "na" ]]; then
      na_total["$profile"]=$(( ${na_total["$profile"]} + 1 ))
    else
      must_total["$profile"]=$(( ${must_total["$profile"]} + 1 ))
      if [[ "$status" == "fail" ]]; then
        must_fail["$profile"]=$(( ${must_fail["$profile"]} + 1 ))
      fi
    fi
  fi
}

check_file() {
  local profile="$1"
  local id="$2"
  local level="$3"
  local description="$4"
  local path="$5"
  if [[ -f "$path" ]]; then
    append_check "$profile" "$id" "$level" "pass" "$description" "$path"
  else
    append_check "$profile" "$id" "$level" "fail" "$description" "$path"
  fi
}

check_rg() {
  local profile="$1"
  local id="$2"
  local level="$3"
  local description="$4"
  local pattern="$5"
  local path="$6"
  local hit=""
  if hit="$(rg -n -m1 "$pattern" "$path" 2>/dev/null)"; then
    append_check "$profile" "$id" "$level" "pass" "$description" "$hit"
  else
    append_check "$profile" "$id" "$level" "fail" "$description" "$path"
  fi
}

check_na() {
  local profile="$1"
  local id="$2"
  local level="$3"
  local description="$4"
  local reason="$5"
  append_check "$profile" "$id" "$level" "na" "$description" "$reason"
}

finish_profile() {
  local profile="$1"
  local path="${report_file[$profile]}"
  local result="pass"
  if [[ ${must_fail["$profile"]} -gt 0 ]]; then
    result="fail"
  fi
  result_status["$profile"]="$result"
  cat >> "$path" <<EOF

  ],
  "summary": {
    "checks_total": ${check_total["$profile"]},
    "must_checks_total": ${must_total["$profile"]},
    "must_not_applicable": ${na_total["$profile"]},
    "must_failed": ${must_fail["$profile"]}
  },
  "result": "$result"
}
EOF
  echo "[conformance] ${profile}: result=${result} must_failed=${must_fail["$profile"]} report=${path}"
}

run_core_node_checks() {
  local p="core-node"
  check_rg "$p" "CN-4.1" "MUST" "Identity record schema exists (username, pubkey, fingerprint, ipv6)." "CREATE TABLE IF NOT EXISTS identities" "internal/identity/store.go"
  check_rg "$p" "CN-4.2" "MUST" "First-claim binding path is implemented." "func \\(s \\*Store\\) Claim" "internal/identity/store.go"
  check_file "$p" "CN-5.1" "MUST" "Discovery artifact template exists for /.well-known/sisu-node publication." "deploy/well-known/sisu-node.example.json"
  check_rg "$p" "CN-5.2" "MUST" "Discovery artifact includes node public key field." "\"node_public_key\"" "deploy/well-known/sisu-node.example.json"
  check_rg "$p" "CN-5.3" "MUST" "Discovery artifact includes endpoints block." "\"endpoints\"" "deploy/well-known/sisu-node.example.json"
  check_rg "$p" "CN-5.4" "MUST" "Relay can serve discovery document over HTTP when enabled." "well-known-listen" "cmd/sisumail-relay/main.go"
  check_file "$p" "CN-5.5" "MUST" "Relay discovery HTTP server implementation exists." "cmd/sisumail-relay/wellknown.go"
  check_rg "$p" "CN-7.1" "MUST" "Envelope path encrypts payload using age." "age\\.Encrypt" "internal/tier2/encrypt.go"
  check_rg "$p" "CN-7.2" "MUST" "Envelope path decrypts payload locally." "age\\.Decrypt" "internal/tier2/encrypt.go"
  check_rg "$p" "CN-11.1" "MUST" "Client receives encrypted spool delivery channel." "HandleChannelOpen\\(\"spool-delivery\"\\)" "cmd/sisumail/main.go"
  check_rg "$p" "CN-11.2" "MUST" "Local API exposes inbox retrieval surface for clients." "HandleFunc\\(\"/v1/inbox\"" "cmd/sisumail/main.go"
  check_file "$p" "CN-13.1" "MUST" "Logging/metadata hygiene policy is documented." "docs/logging-hygiene.md"
  check_file "$p" "CN-15.5" "MUST" "Conformance declaration exists." "conformance/declaration.json"
  check_rg "$p" "CN-15.5a" "MUST" "Conformance declaration includes version target." "\"version_target\"" "conformance/declaration.json"
  check_rg "$p" "CN-15.5b" "MUST" "Conformance declaration includes profile list." "\"profiles\"" "conformance/declaration.json"
}

run_relay_node_checks() {
  local p="relay-node"
  check_rg "$p" "RN-9.1" "MUST" "Tier 1 blind relay proxy exists." "type Tier1Proxy struct" "internal/relay/tier1_proxy.go"
  check_rg "$p" "RN-9.2" "MUST" "Tier 2 SMTP ingress bridge exists." "smtp\\.NewServer" "cmd/sisumail-tier2/main.go"
  check_rg "$p" "RN-9.3" "MUST" "Split MX routing template is documented." "10 v6\\.<u>\\.sisumail\\.fi\\." "docs/dns-records.md"
  check_rg "$p" "RN-9.4" "MUST" "Tier 2 STARTTLS policy modes are implemented." "parseTLSMode" "cmd/sisumail-tier2/main.go"
  check_na "$p" "RN-9.5" "MUST" "Null MX behavior" "Receive-only ingress implementation does not perform outbound MX resolution in v1."
  check_rg "$p" "RN-10.1" "MUST" "AnyIP deployment controls are documented." "ip_nonlocal_bind" "docs/operator-quickstart.md"
  check_file "$p" "RN-13.1" "MUST" "Relay metadata/logging hygiene policy is documented." "docs/logging-hygiene.md"
  check_file "$p" "RN-15.5" "MUST" "Conformance declaration exists." "conformance/declaration.json"
}

run_client_checks() {
  local p="client"
  check_rg "$p" "CL-11.1" "MUST" "Client performs local decrypt for Tier 2 spool messages." "tier2\\.StreamDecrypt" "cmd/sisumail/main.go"
  check_rg "$p" "CL-11.2" "MUST" "Client renders email body types text/plain and text/html." "text/plain" "cmd/sisumail/main.go"
  check_rg "$p" "CL-11.3" "MUST" "Client supports multipart message handling." "multipart/" "cmd/sisumail/main.go"
  check_rg "$p" "CL-11.4" "MUST" "Client app/API exposes message read endpoint." "HandleFunc\\(\"/v1/message/\"" "cmd/sisumail/main.go"
  check_rg "$p" "CL-11.5" "MUST" "Client app/API exposes inbox endpoint." "HandleFunc\\(\"/v1/inbox\"" "cmd/sisumail/main.go"
  check_rg "$p" "CL-14.1" "SHOULD" "Client surfaces TLS trust state to user." "tls_authenticated_ca" "cmd/sisumail/main.go"
  check_file "$p" "CL-15.5" "MUST" "Conformance declaration exists." "conformance/declaration.json"
}

known_profile() {
  case "$1" in
    core-node|relay-node|client) return 0 ;;
    *) return 1 ;;
  esac
}

for profile in "${profiles[@]}"; do
  if ! known_profile "$profile"; then
    echo "unknown profile: $profile" >&2
    exit 2
  fi
  start_profile "$profile"
  case "$profile" in
    core-node) run_core_node_checks ;;
    relay-node) run_relay_node_checks ;;
    client) run_client_checks ;;
  esac
  finish_profile "$profile"
done

if [[ "$strict" == "1" ]]; then
  for profile in "${profiles[@]}"; do
    if [[ "${result_status[$profile]}" != "pass" ]]; then
      exit 1
    fi
  done
fi

exit 0
