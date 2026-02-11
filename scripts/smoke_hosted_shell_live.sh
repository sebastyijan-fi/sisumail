#!/usr/bin/env bash
set -euo pipefail

# Live smoke test for hosted SSH shell UX on sisumail.fi (or another relay host).
# Requires an already-claimed user key.

SSH_HOST="${SSH_HOST:-sisumail.fi}"
SSH_PORT="${SSH_PORT:-22}"
SSH_USER="${SSH_USER:-}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/id_ed25519}"
KNOWN_HOSTS="${KNOWN_HOSTS:-/tmp/sisu_smoke_hosted_shell_kh}"

if [[ -z "${SSH_USER}" ]]; then
  echo "[smoke-hosted-shell] FAIL: set SSH_USER=<claimed_username>" >&2
  exit 1
fi
if [[ ! -f "${SSH_KEY}" ]]; then
  echo "[smoke-hosted-shell] FAIL: key not found: ${SSH_KEY}" >&2
  exit 1
fi

run_shell() {
  local input="$1"
  printf "%b" "${input}" | ssh -tt \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="${KNOWN_HOSTS}" \
    -p "${SSH_PORT}" \
    -i "${SSH_KEY}" \
    "${SSH_USER}@${SSH_HOST}" 2>&1
}

echo "[smoke-hosted-shell] host=${SSH_HOST}:${SSH_PORT} user=${SSH_USER}"

echo "[smoke-hosted-shell] check help/whoami/status"
out1="$(run_shell $'¤help\n¤whoami\n¤status\n¤quit\n')"
if ! grep -q "Sisumail Hosted Shell" <<<"${out1}"; then
  echo "[smoke-hosted-shell] FAIL: missing shell banner"
  echo "${out1}"
  exit 1
fi
if ! grep -q "user=${SSH_USER}" <<<"${out1}"; then
  echo "[smoke-hosted-shell] FAIL: whoami did not report expected user"
  echo "${out1}"
  exit 1
fi
if ! grep -q "chat_queue=" <<<"${out1}"; then
  echo "[smoke-hosted-shell] FAIL: status output missing queue counters"
  echo "${out1}"
  exit 1
fi

echo "[smoke-hosted-shell] send self-message and verify delivery status text"
out2="$(run_shell $'¤'"${SSH_USER}"$' smoke-hosted-shell-live\n¤quit\n')"
if ! grep -Eq "delivered-live|queued-encrypted" <<<"${out2}"; then
  echo "[smoke-hosted-shell] FAIL: send output missing delivery mode"
  echo "${out2}"
  exit 1
fi

echo "[smoke-hosted-shell] check chat queue command"
out3="$(run_shell $'¤chatq\n¤quit\n')"
if ! grep -q "queued chat messages:" <<<"${out3}"; then
  echo "[smoke-hosted-shell] FAIL: chatq output missing"
  echo "${out3}"
  exit 1
fi

echo "[smoke-hosted-shell] OK"
