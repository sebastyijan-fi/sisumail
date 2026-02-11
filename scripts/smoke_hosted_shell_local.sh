#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
if [[ "${KEEP_TMP:-0}" == "1" ]]; then
  trap 'set +e; kill $(jobs -pr) 2>/dev/null' EXIT
else
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; rm -rf "$tmp"' EXIT
fi

SSH_PORT=36222

echo "[smoke-hosted-local] tmp=$tmp"
echo "[smoke-hosted-local] generate ssh key"
ssh-keygen -t ed25519 -N '' -f "$tmp/user_key" -C "hosted-local" >/dev/null

echo "[smoke-hosted-local] start relay"
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

echo "[smoke-hosted-local] seed identity"
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user -username alice -pubkey "$tmp/user_key.pub" -ipv6 "2a01:db8::1" >/dev/null

kh="$tmp/known_hosts"

echo "[smoke-hosted-local] run hosted shell commands"
out="$tmp/shell.out"
printf '¤help\n¤whoami\n¤status\n¤alice hello-self\n¤chatq\n¤quit\n' | ssh -tt \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$kh" \
  -i "$tmp/user_key" \
  -p "$SSH_PORT" \
  alice@127.0.0.1 \
  >"$out" 2>&1 || {
  echo "[smoke-hosted-local] FAIL: ssh command failed"
  cat "$out"
  echo "--- relay log ---"
  cat "$tmp/relay.log"
  exit 1
}

if ! rg -n "Sisumail Hosted Shell" "$out" >/dev/null; then
  echo "[smoke-hosted-local] FAIL: missing shell banner"
  cat "$out"
  exit 1
fi
if ! rg -n "user=alice" "$out" >/dev/null; then
  echo "[smoke-hosted-local] FAIL: whoami mismatch"
  cat "$out"
  exit 1
fi
if ! rg -n "chat_queue=.*mail_queue=" "$out" >/dev/null; then
  echo "[smoke-hosted-local] FAIL: status output missing"
  cat "$out"
  exit 1
fi
if ! rg -n "delivered-live|queued-encrypted" "$out" >/dev/null; then
  echo "[smoke-hosted-local] FAIL: send output missing delivery mode"
  cat "$out"
  exit 1
fi
if ! rg -n "queued chat messages:" "$out" >/dev/null; then
  echo "[smoke-hosted-local] FAIL: chatq output missing"
  cat "$out"
  exit 1
fi

echo "[smoke-hosted-local] OK"
