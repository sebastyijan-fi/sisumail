#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage:
  scripts/generate_well_known_sisu_node.sh \
    --domain sisumail.fi \
    --node-public-key <base64-ed25519-pubkey> \
    --ssh-endpoint sisumail.fi:2222 \
    --tier2-smtp spool.sisumail.fi:25 \
    [--tier1-smtp <user>.v6.sisumail.fi:25] \
    [--api-endpoint https://sisumail.fi] \
    [--well-known-url https://sisumail.fi/.well-known/sisu-node] \
    [--profile core-node --profile relay-node --profile client] \
    [--out deploy/well-known/sisu-node.generated.json]

Generates a publishable .well-known/sisu-node JSON document.
EOF
}

domain=""
node_public_key=""
ssh_endpoint=""
tier1_smtp=""
tier2_smtp=""
api_endpoint=""
well_known_url=""
out_path="deploy/well-known/sisu-node.generated.json"
profiles=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      domain="${2:-}"
      shift 2
      ;;
    --node-public-key)
      node_public_key="${2:-}"
      shift 2
      ;;
    --ssh-endpoint)
      ssh_endpoint="${2:-}"
      shift 2
      ;;
    --tier1-smtp)
      tier1_smtp="${2:-}"
      shift 2
      ;;
    --tier2-smtp)
      tier2_smtp="${2:-}"
      shift 2
      ;;
    --api-endpoint)
      api_endpoint="${2:-}"
      shift 2
      ;;
    --well-known-url)
      well_known_url="${2:-}"
      shift 2
      ;;
    --profile)
      profiles+=("${2:-}")
      shift 2
      ;;
    --out)
      out_path="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$domain" || -z "$node_public_key" || -z "$ssh_endpoint" || -z "$tier2_smtp" ]]; then
  echo "error: --domain, --node-public-key, --ssh-endpoint and --tier2-smtp are required" >&2
  usage
  exit 2
fi

if [[ ${#profiles[@]} -eq 0 ]]; then
  profiles=("core-node" "relay-node" "client")
fi

if [[ -z "$tier1_smtp" ]]; then
  tier1_smtp="<user>.v6.${domain}:25"
fi
if [[ -z "$api_endpoint" ]]; then
  api_endpoint="https://${domain}"
fi

if [[ -z "$well_known_url" ]]; then
  well_known_url="https://${domain}/.well-known/sisu-node"
fi
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

profiles_json=""
for p in "${profiles[@]}"; do
  p="$(printf "%s" "$p" | tr -d '[:space:]')"
  if [[ -z "$p" ]]; then
    continue
  fi
  if [[ -n "$profiles_json" ]]; then
    profiles_json+=", "
  fi
  profiles_json+="\"$p\""
done

mkdir -p "$(dirname "$out_path")"
cat > "$out_path" <<EOF
{
  "version": "sisu-v1",
  "generated_at": "$generated_at",
  "domain": "$domain",
  "well_known_url": "$well_known_url",
  "node_public_key": "$node_public_key",
  "profiles": [$profiles_json],
  "endpoints": {
    "ssh": "$ssh_endpoint",
    "tier1_smtp": "$tier1_smtp",
    "tier2_smtp": "$tier2_smtp",
    "api": "$api_endpoint"
  },
  "policy": {
    "receive_only": true,
    "outbound_email_supported": false
  }
}
EOF

echo "wrote $out_path"
