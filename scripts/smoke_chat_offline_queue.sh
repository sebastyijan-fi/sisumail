#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'set +e; kill $(jobs -pr) 2>/dev/null; rm -rf "$tmp"' EXIT

SSH_PORT=36222
SMTP_PORT_ALICE=36528
SMTP_PORT_BOB=36527

echo "[smoke-chat-offline] tmp=$tmp"
echo "[smoke-chat-offline] generate ssh keys"
ssh-keygen -t ed25519 -N '' -f "$tmp/alice_key" -C "alice-chat-offline" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$tmp/bob_key" -C "bob-chat-offline" >/dev/null

echo "[smoke-chat-offline] start relay"
go run ./cmd/sisumail-relay \
  -ssh-listen "127.0.0.1:${SSH_PORT}" \
  -tier1-listen "127.0.0.1:0" \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -spool-dir "$tmp/spool" \
  -chat-spool-dir "$tmp/chatspool" \
  -allow-claim=false \
  >/dev/null 2>"$tmp/relay.log" &

sleep 0.5

echo "[smoke-chat-offline] seed identities"
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user -username alice -pubkey "$tmp/alice_key.pub" -ipv6 "2a01:db8::1" >/dev/null
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user -username bob -pubkey "$tmp/bob_key.pub" -ipv6 "2a01:db8::2" >/dev/null

echo "[smoke-chat-offline] send chat from alice -> bob while bob is offline"
go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user alice \
  -key "$tmp/alice_key" \
  -insecure-host-key \
  -smtp-listen "127.0.0.1:${SMTP_PORT_ALICE}" \
  -tls-policy pragmatic \
  -chat-dir "$tmp/alice-chat" \
  -chat-to bob \
  -chat-msg "queued hello" \
  >"$tmp/alice.out" 2>&1

echo "[smoke-chat-offline] assert queued ciphertext exists"
ls -1 "$tmp/chatspool/bob"/*.chat >/dev/null

echo "[smoke-chat-offline] start bob client and wait for queued delivery"
timeout 12s go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user bob \
  -key "$tmp/bob_key" \
  -insecure-host-key \
  -smtp-listen "127.0.0.1:${SMTP_PORT_BOB}" \
  -tls-policy pragmatic \
  -chat-dir "$tmp/bob-chat" \
  >"$tmp/bob.out" 2>&1 &

for _ in $(seq 1 40); do
  if rg -n 'chat-delivery: from=alice msg="queued hello"' "$tmp/bob.out" >/dev/null; then
    break
  fi
  sleep 0.2
done

if ! rg -n 'chat-delivery: from=alice msg="queued hello"' "$tmp/bob.out" >/dev/null; then
  echo "[smoke-chat-offline] FAIL: bob did not receive queued chat"
  echo "--- bob ---"
  cat "$tmp/bob.out"
  echo "--- alice ---"
  cat "$tmp/alice.out"
  echo "--- relay ---"
  cat "$tmp/relay.log"
  exit 1
fi

echo "[smoke-chat-offline] assert queue is acked (empty)"
if compgen -G "$tmp/chatspool/bob/*.chat" >/dev/null; then
  echo "[smoke-chat-offline] FAIL: queued ciphertext still present"
  ls -la "$tmp/chatspool/bob"
  exit 1
fi

echo "[smoke-chat-offline] OK"
