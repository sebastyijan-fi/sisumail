#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'set +e; kill $(jobs -pr) 2>/dev/null; rm -rf "$tmp"' EXIT

SSH_PORT=37222
TIER2_PORT=37526
SMTP_PORT=37527
API_PORT=37990

echo "[dogfood-email] tmp=${tmp}"
echo "[dogfood-email] generate ssh key for niklas"
ssh-keygen -t ed25519 -N '' -f "$tmp/niklas_key" -C "niklas-dogfood-email" >/dev/null

echo "[dogfood-email] start relay"
go run ./cmd/sisumail-relay \
  -ssh-listen "127.0.0.1:${SSH_PORT}" \
  -tier1-listen "127.0.0.1:0" \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -spool-dir "$tmp/spool" \
  -allow-claim=false \
  >/dev/null 2>"$tmp/relay.log" &

sleep 0.6

echo "[dogfood-email] seed identity niklas"
go run ./cmd/sisumail-relay \
  -db "$tmp/relay.db" \
  -hostkey "$tmp/hostkey_ed25519" \
  -add-user \
  -username niklas \
  -pubkey "$tmp/niklas_key.pub" \
  -ipv6 "2a01:db8::5" \
  >/dev/null

echo "[dogfood-email] start tier2"
go run ./cmd/sisumail-tier2 \
  -listen "127.0.0.1:${TIER2_PORT}" \
  -zone "sisumail.fi" \
  -db "$tmp/relay.db" \
  -spool-dir "$tmp/spool" \
  >/dev/null 2>"$tmp/tier2.log" &

sleep 0.6

echo "[dogfood-email] start sisumail with local app API"
timeout 40s go run ./cmd/sisumail \
  -relay "127.0.0.1:${SSH_PORT}" \
  -user niklas \
  -key "$tmp/niklas_key" \
  -insecure-host-key \
  -smtp-listen "127.0.0.1:${SMTP_PORT}" \
  -tls-policy pragmatic \
  -acme-dns01=false \
  -config "$tmp/config.env" \
  -maildir "$tmp/maildir" \
  -chat-dir "$tmp/chat" \
  -known-keys "$tmp/known_keys.json" \
  -api-listen "127.0.0.1:${API_PORT}" \
  -api-token-path "$tmp/api-token" \
  >"$tmp/client.out" 2>&1 &

sleep 1.2

if [[ ! -f "$tmp/api-token" ]]; then
  echo "[dogfood-email] FAIL: api token file missing"
  cat "$tmp/client.out"
  exit 1
fi
token="$(tr -d '\r\n' < "$tmp/api-token")"

echo "[dogfood-email] wait for local API readiness"
for _ in $(seq 1 30); do
  if curl -fsS -H "Authorization: Bearer ${token}" "http://127.0.0.1:${API_PORT}/v1/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "[dogfood-email] inject test email"
printf "EHLO x\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<inbox@niklas.sisumail.fi>\r\nDATA\r\nSubject: dogfood-email\r\n\r\nhello-from-dogfood\r\n.\r\nQUIT\r\n" \
  | nc -w 2 127.0.0.1 "${TIER2_PORT}" >/dev/null

sleep 1.0

echo "[dogfood-email] query /v1/status"
status_json="$(curl -fsS -H "Authorization: Bearer ${token}" "http://127.0.0.1:${API_PORT}/v1/status")"
echo "$status_json" | rg -n '"user": "niklas"' >/dev/null || {
  echo "[dogfood-email] FAIL: status response missing user"
  echo "$status_json"
  exit 1
}

echo "[dogfood-email] query /v1/inbox"
inbox_json="$(curl -fsS -H "Authorization: Bearer ${token}" "http://127.0.0.1:${API_PORT}/v1/inbox")"
echo "$inbox_json" | rg -n '"subject": "dogfood-email"' >/dev/null || {
  echo "[dogfood-email] FAIL: inbox missing expected subject"
  echo "$inbox_json"
  echo "--- client ---"
  cat "$tmp/client.out"
  exit 1
}
msg_id="$(echo "$inbox_json" | rg -o '"id":\s*"[^"]+"' -m1 | sed -E 's/.*"id":\s*"([^"]+)".*/\1/')"
if [[ -z "${msg_id}" ]]; then
  echo "[dogfood-email] FAIL: could not parse message id"
  echo "$inbox_json"
  exit 1
fi

echo "[dogfood-email] query /v1/message/${msg_id}"
msg_raw="$(curl -fsS -H "Authorization: Bearer ${token}" "http://127.0.0.1:${API_PORT}/v1/message/${msg_id}")"
echo "$msg_raw" | rg -n "Subject: dogfood-email" >/dev/null || {
  echo "[dogfood-email] FAIL: message endpoint missing subject"
  echo "$msg_raw"
  exit 1
}

echo "[dogfood-email] OK"
