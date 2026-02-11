#!/usr/bin/env bash
set -euo pipefail

# Live smoke test for relay-mediated ACME DNS-01 flow.
# Run on the relay/node host with sisumail binaries installed.
#
# Defaults:
# - ACME staging directory (safe for repeated tests)
# - relay at 127.0.0.1:2222
# - zone from /etc/sisumail.env (fallback sisumail.fi)
#
# Required local state:
# - /var/lib/sisumail/relay.db
# - relay service running with DNS env configured (HCLOUD_TOKEN + SISUMAIL_DNS_ZONE)

RELAY_ADDR="${RELAY_ADDR:-127.0.0.1:2222}"
SMTP_LISTEN="${SMTP_LISTEN:-127.0.0.1:2726}"
ZONE="${ZONE:-}"
ACME_DIR="${ACME_DIR:-https://acme-staging-v02.api.letsencrypt.org/directory}"
PROP_WAIT="${PROP_WAIT:-35s}"
TIMEOUT_SECS="${TIMEOUT_SECS:-360}"
DB_PATH="${DB_PATH:-/var/lib/sisumail/relay.db}"

if [[ -f /etc/sisumail.env ]]; then
  # shellcheck disable=SC1091
  . /etc/sisumail.env
fi

if [[ -z "${ZONE}" ]]; then
  ZONE="${SISUMAIL_DNS_ZONE:-sisumail.fi}"
fi

if [[ ! -x /usr/local/bin/sisumail ]]; then
  echo "[smoke-acme-live] FAIL: /usr/local/bin/sisumail not found" >&2
  exit 1
fi
if [[ ! -x /usr/local/bin/sisumail-relay ]]; then
  echo "[smoke-acme-live] FAIL: /usr/local/bin/sisumail-relay not found" >&2
  exit 1
fi
if [[ ! -f "${DB_PATH}" ]]; then
  echo "[smoke-acme-live] FAIL: db not found at ${DB_PATH}" >&2
  exit 1
fi

u="acme$(date +%m%d%H%M%S)"
tmp="$(mktemp -d)"
out="${tmp}/client.log"
key="${tmp}/${u}_key"
host="v6.${u}.${ZONE}"
crt="${HOME}/.local/share/sisumail/tls/${host}.crt.pem"
keypem="${HOME}/.local/share/sisumail/tls/${host}.key.pem"
challenge="_acme-challenge.${host}"

trap 'set +e; rm -rf "${tmp}"' EXIT

echo "[smoke-acme-live] user=${u}"
echo "[smoke-acme-live] zone=${ZONE} relay=${RELAY_ADDR} smtp=${SMTP_LISTEN}"
echo "[smoke-acme-live] acme_dir=${ACME_DIR}"

if ! systemctl is-active --quiet sisumail-relay; then
  echo "[smoke-acme-live] FAIL: sisumail-relay is not active" >&2
  exit 1
fi

ssh-keygen -t ed25519 -N '' -f "${key}" -C "${u}-smoke-acme-live" >/dev/null

prefix="${SISUMAIL_IPV6_PREFIX:-}"
if [[ -z "${prefix}" ]]; then
  echo "[smoke-acme-live] FAIL: SISUMAIL_IPV6_PREFIX is not set" >&2
  exit 1
fi
prefix_base="${prefix%%/*}"
suffix_hex="$(printf '%x' "$(( (RANDOM % 60000) + 4096 ))")"
if [[ "${prefix_base}" == *"::" ]]; then
  ip="${prefix_base}${suffix_hex}"
else
  ip="${prefix_base}::${suffix_hex}"
fi

/usr/local/bin/sisumail-relay \
  -db "${DB_PATH}" \
  -add-user \
  -username "${u}" \
  -pubkey "${key}.pub" \
  -ipv6 "${ip}" \
  >/dev/null

set +e
timeout "${TIMEOUT_SECS}" /usr/local/bin/sisumail \
  -relay "${RELAY_ADDR}" \
  -user "${u}" \
  -key "${key}" \
  -zone "${ZONE}" \
  -smtp-listen "${SMTP_LISTEN}" \
  -tls-policy strict \
  -acme-dns01 \
  -acme-via-relay=true \
  -acme-directory-url "${ACME_DIR}" \
  -acme-check-interval 0s \
  -acme-propagation-wait "${PROP_WAIT}" \
  >"${out}" 2>&1
rc=$?
set -e

if [[ "${rc}" -ne 0 && "${rc}" -ne 124 ]]; then
  echo "[smoke-acme-live] FAIL: sisumail exit=${rc}"
  sed -n '1,200p' "${out}" || true
  exit 1
fi

if [[ ! -s "${crt}" || ! -s "${keypem}" ]]; then
  echo "[smoke-acme-live] FAIL: cert/key not created"
  echo "  cert=${crt}"
  echo "  key=${keypem}"
  sed -n '1,200p' "${out}" || true
  exit 1
fi

subject="$(openssl x509 -in "${crt}" -noout -subject | sed 's/^subject=//')"
if ! echo "${subject}" | grep -F "CN = ${host}" >/dev/null && ! echo "${subject}" | grep -F "CN=${host}" >/dev/null; then
  echo "[smoke-acme-live] FAIL: subject mismatch"
  echo "  subject=${subject}"
  exit 1
fi

if command -v dig >/dev/null 2>&1; then
  txt_left="$(dig +short TXT "${challenge}" | tr '\n' ';')"
  if [[ -n "${txt_left}" ]]; then
    echo "[smoke-acme-live] FAIL: challenge TXT not cleaned up"
    echo "  ${challenge} => ${txt_left}"
    exit 1
  fi
fi

issuer="$(openssl x509 -in "${crt}" -noout -issuer | sed 's/^issuer=//')"
dates="$(openssl x509 -in "${crt}" -noout -dates | tr '\n' ' ')"

echo "[smoke-acme-live] OK"
echo "[smoke-acme-live] host=${host}"
echo "[smoke-acme-live] subject=${subject}"
echo "[smoke-acme-live] issuer=${issuer}"
echo "[smoke-acme-live] dates=${dates}"
echo "[smoke-acme-live] log_tail:"
tail -n 40 "${out}" || true
