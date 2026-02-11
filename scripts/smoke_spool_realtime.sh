#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'set +e; kill $(jobs -pr) 2>/dev/null; rm -rf "$tmp"' EXIT

SSH_PORT=33222
TIER2_PORT=33526
SMTP_PORT=33527

echo "[smoke-rt] tmp=$tmp"
echo "[smoke-rt] generate ssh key for alice"
ssh-keygen -t ed25519 -N '' -f "$tmp/alice_key" -C "alice-smoke-rt" >/dev/null

echo "[smoke-rt] start relay"
go run ./cmd/sisumail-relay \
  -ssh-listen "127.0.0.1:${SSH_PORT}" \
  -tier1-listen "127.0.0.1:0" \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -spool-dir "$tmp/spool" \
  -allow-claim=false \
  >/dev/null 2>"$tmp/relay.log" &

sleep 0.5

echo "[smoke-rt] seed identity alice"
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user \
  -username alice \
  -pubkey "$tmp/alice_key.pub" \
  -ipv6 "2a01:db8::1" \
  >/dev/null

echo "[smoke-rt] start tier2 (staging, no TLS)"
go run ./cmd/sisumail-tier2 \
  -listen "127.0.0.1:${TIER2_PORT}" \
  -zone "sisumail.fi" \
  -db "$tmp/relay.db" \
  -spool-dir "$tmp/spool" \
  >/dev/null 2>"$tmp/tier2.log" &

sleep 0.5

echo "[smoke-rt] start client and keep it connected"
timeout 12s go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user alice \
  -key "$tmp/alice_key" \
  -smtp-listen "127.0.0.1:${SMTP_PORT}" \
  -tls-policy pragmatic \
  >"$tmp/client.out" 2>&1 &

sleep 1.0

echo "[smoke-rt] inject message into tier2 while client is online"
printf "EHLO x\r\nMAIL FROM:<s@e>\r\nRCPT TO:<mail+steam@alice.sisumail.fi>\r\nDATA\r\nSubject: realtime\r\n\r\nhello-live\r\n.\r\nQUIT\r\n" | nc -w 2 127.0.0.1 "${TIER2_PORT}" >/dev/null

echo "[smoke-rt] wait for real-time spool-delivery signal"
for _ in $(seq 1 40); do
  if rg -n "spool-delivery: msg=" "$tmp/client.out" >/dev/null; then
    break
  fi
  sleep 0.2
done

if ! rg -n "spool-delivery: msg=" "$tmp/client.out" >/dev/null; then
  echo "[smoke-rt] FAIL: no realtime spool-delivery observed"
  echo "--- client output ---"
  cat "$tmp/client.out"
  echo "--- relay log ---"
  cat "$tmp/relay.log" || true
  echo "--- tier2 log ---"
  cat "$tmp/tier2.log" || true
  exit 1
fi

echo "[smoke-rt] check spool is acked (empty)"
if compgen -G "$tmp/spool/alice/*.age" >/dev/null; then
  echo "[smoke-rt] FAIL: spool ciphertext still present after ACK"
  ls -la "$tmp/spool/alice"
  exit 1
fi

echo "[smoke-rt] OK"
