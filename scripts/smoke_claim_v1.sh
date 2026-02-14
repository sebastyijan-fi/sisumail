#!/usr/bin/env bash
set -euo pipefail

# Local smoke: invite mint + claim-v1 channel.
# This does NOT touch real DNS. It allocates from SISUMAIL_IPV6_PREFIX only.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export SISUMAIL_IPV6_PREFIX="fd00:1::/64"
export SISUMAIL_DEV_CLAIM_NO_PROVISION=1
export SISUMAIL_INVITE_PEPPER="dev-pepper"

db="$tmp/relay.db"
hostkey="$tmp/relay_hostkey_ed25519"
clientkey="$tmp/client_ed25519"

ssh-keygen -q -t ed25519 -N "" -f "$clientkey" >/dev/null

go run ./cmd/sisumail-relay -db "$db" -hostkey "$hostkey" -init-db >/dev/null
code="$(go run ./cmd/sisumail-relay -db "$db" -hostkey "$hostkey" -mint-invites -mint-invites-n 1)"

go run ./cmd/sisumail-relay -db "$db" -hostkey "$hostkey" -ssh-listen 127.0.0.1:2222 -tier1-listen 127.0.0.1:2525 >/dev/null 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

sleep 0.2

go run ./cmd/sisumail -relay 127.0.0.1:2222 -key "$clientkey" -known-hosts "$tmp/known_hosts" -insecure-host-key \
  -claim alice -claim-invite "$code"

