#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'set +e; kill $(jobs -pr) 2>/dev/null; rm -rf "$tmp"' EXIT

SSH_PORT=34222
SMTP_PORT_BOB=34527
SMTP_PORT_ALICE=34528

echo "[smoke-chat] tmp=$tmp"
echo "[smoke-chat] generate ssh keys"
ssh-keygen -t ed25519 -N '' -f "$tmp/alice_key" -C "alice-chat" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$tmp/bob_key" -C "bob-chat" >/dev/null

echo "[smoke-chat] start relay"
go run ./cmd/sisumail-relay \
  -ssh-listen "127.0.0.1:${SSH_PORT}" \
  -tier1-listen "127.0.0.1:0" \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -spool-dir "$tmp/spool" \
  -allow-claim=false \
  >/dev/null 2>"$tmp/relay.log" &

sleep 0.5

echo "[smoke-chat] seed identities"
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user -username alice -pubkey "$tmp/alice_key.pub" -ipv6 "2a01:db8::1" >/dev/null
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user -username bob -pubkey "$tmp/bob_key.pub" -ipv6 "2a01:db8::2" >/dev/null

echo "[smoke-chat] start bob client (receiver)"
timeout 10s go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user bob \
  -key "$tmp/bob_key" \
  -smtp-listen "127.0.0.1:${SMTP_PORT_BOB}" \
  -tls-policy pragmatic \
  >"$tmp/bob.out" 2>&1 &

sleep 1

echo "[smoke-chat] send chat from alice -> bob"
go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user alice \
  -key "$tmp/alice_key" \
  -smtp-listen "127.0.0.1:${SMTP_PORT_ALICE}" \
  -tls-policy pragmatic \
  -chat-to bob \
  -chat-msg "hello bob from alice" \
  >"$tmp/alice.out" 2>&1

for _ in $(seq 1 30); do
  if rg -n 'chat-delivery: from=alice msg="hello bob from alice"' "$tmp/bob.out" >/dev/null; then
    break
  fi
  sleep 0.2
done

if ! rg -n 'chat-delivery: from=alice msg="hello bob from alice"' "$tmp/bob.out" >/dev/null; then
  echo "[smoke-chat] FAIL: bob did not receive expected chat"
  echo "--- bob ---"
  cat "$tmp/bob.out"
  echo "--- alice ---"
  cat "$tmp/alice.out"
  echo "--- relay ---"
  cat "$tmp/relay.log"
  exit 1
fi

echo "[smoke-chat] OK"
