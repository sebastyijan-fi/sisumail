#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'set +e; kill $(jobs -pr) 2>/dev/null; rm -rf "$tmp"' EXIT

SSH_PORT=35222
SMTP_PORT_BOB=35527
SMTP_PORT_ALICE=35528

echo "[smoke-chat-repl] tmp=$tmp"
echo "[smoke-chat-repl] generate ssh keys"
ssh-keygen -t ed25519 -N '' -f "$tmp/alice_key" -C "alice-chat-repl" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$tmp/bob_key" -C "bob-chat-repl" >/dev/null

echo "[smoke-chat-repl] start relay"
go run ./cmd/sisumail-relay \
  -ssh-listen "127.0.0.1:${SSH_PORT}" \
  -tier1-listen "127.0.0.1:0" \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -spool-dir "$tmp/spool" \
  -allow-claim=false \
  >/dev/null 2>"$tmp/relay.log" &

sleep 0.5

echo "[smoke-chat-repl] seed identities"
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user -username alice -pubkey "$tmp/alice_key.pub" -ipv6 "2a01:db8::1" >/dev/null
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user -username bob -pubkey "$tmp/bob_key.pub" -ipv6 "2a01:db8::2" >/dev/null

echo "[smoke-chat-repl] start bob client (receiver)"
timeout 12s go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user bob \
  -key "$tmp/bob_key" \
  -insecure-host-key \
  -smtp-listen "127.0.0.1:${SMTP_PORT_BOB}" \
  -tls-policy pragmatic \
  -chat-dir "$tmp/bob-chat" \
  >"$tmp/bob.out" 2>&1 &

sleep 1

echo "[smoke-chat-repl] run alice chat repl (send one line then quit)"
printf "hello from repl\n/quit\n" | go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user alice \
  -key "$tmp/alice_key" \
  -insecure-host-key \
  -smtp-listen "127.0.0.1:${SMTP_PORT_ALICE}" \
  -tls-policy pragmatic \
  -chat-dir "$tmp/alice-chat" \
  -chat-with bob \
  >"$tmp/alice.out" 2>&1

for _ in $(seq 1 30); do
  if rg -n 'chat-delivery: from=alice msg="hello from repl"' "$tmp/bob.out" >/dev/null; then
    break
  fi
  sleep 0.2
done

if ! rg -n 'chat-delivery: from=alice msg="hello from repl"' "$tmp/bob.out" >/dev/null; then
  echo "[smoke-chat-repl] FAIL: bob did not receive repl message"
  echo "--- bob ---"
  cat "$tmp/bob.out"
  echo "--- alice ---"
  cat "$tmp/alice.out"
  echo "--- relay ---"
  cat "$tmp/relay.log"
  exit 1
fi

echo "[smoke-chat-repl] verify alice chat history persisted"
if ! go run ./cmd/sisumail -chat-dir "$tmp/alice-chat" -chat-history bob | rg -n "OUT hello from repl" >/dev/null; then
  echo "[smoke-chat-repl] FAIL: alice chat history missing outgoing line"
  go run ./cmd/sisumail -chat-dir "$tmp/alice-chat" -chat-history bob || true
  exit 1
fi

echo "[smoke-chat-repl] OK"
