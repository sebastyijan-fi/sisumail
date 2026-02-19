#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://sisumail.fi}"
LOCAL_API="${LOCAL_API:-http://127.0.0.1:8080}"
STATE_DIR="${STATE_DIR:-/var/lib/sisumail-smoke}"
ENV_FILE="${ENV_FILE:-/etc/sisumail-relay.env}"

mkdir -p "${STATE_DIR}"
chmod 700 "${STATE_DIR}" || true

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "env file missing: ${ENV_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

if [[ -z "${SISUMAIL_ADMIN_TOKEN:-}" ]]; then
  echo "SISUMAIL_ADMIN_TOKEN missing in ${ENV_FILE}" >&2
  exit 1
fi
if [[ -z "${SISUMAIL_METRICS_TOKEN:-}" ]]; then
  echo "SISUMAIL_METRICS_TOKEN missing in ${ENV_FILE}" >&2
  exit 1
fi

curl_json() {
  local method="$1"
  local url="$2"
  local auth="${3:-}"
  local body="${4:-}"
  local out="$5"
  local code
  if [[ -n "${auth}" && -n "${body}" ]]; then
    code="$(curl -sS -o "${out}" -w "%{http_code}" -X "${method}" -H "Authorization: Bearer ${auth}" -H "Content-Type: application/json" --data "${body}" "${url}")"
  elif [[ -n "${auth}" ]]; then
    code="$(curl -sS -o "${out}" -w "%{http_code}" -X "${method}" -H "Authorization: Bearer ${auth}" "${url}")"
  elif [[ -n "${body}" ]]; then
    code="$(curl -sS -o "${out}" -w "%{http_code}" -X "${method}" -H "Content-Type: application/json" --data "${body}" "${url}")"
  else
    code="$(curl -sS -o "${out}" -w "%{http_code}" -X "${method}" "${url}")"
  fi
  echo "${code}"
}

ready_code="$(curl_json GET "${BASE_URL}/readyz" "" "" "${STATE_DIR}/readyz.json")"
[[ "${ready_code}" == "200" ]] || { echo "readyz failed: ${ready_code}" >&2; cat "${STATE_DIR}/readyz.json" >&2; exit 1; }

metrics_pub_code="$(curl_json GET "${BASE_URL}/metrics" "" "" "${STATE_DIR}/metrics_public.json")"
[[ "${metrics_pub_code}" == "401" ]] || { echo "metrics public expected 401 got ${metrics_pub_code}" >&2; cat "${STATE_DIR}/metrics_public.json" >&2; exit 1; }

metrics_auth_code="$(curl_json GET "${BASE_URL}/metrics" "${SISUMAIL_METRICS_TOKEN}" "" "${STATE_DIR}/metrics_auth.txt")"
[[ "${metrics_auth_code}" == "200" ]] || { echo "metrics auth failed: ${metrics_auth_code}" >&2; cat "${STATE_DIR}/metrics_auth.txt" >&2; exit 1; }

mint_code="$(curl_json POST "${LOCAL_API}/v1/admin/mint-invites" "${SISUMAIL_ADMIN_TOKEN}" '{"n":1}' "${STATE_DIR}/mint.json")"
[[ "${mint_code}" == "200" ]] || { echo "mint failed: ${mint_code}" >&2; cat "${STATE_DIR}/mint.json" >&2; exit 1; }
invite="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["invites"][0])' "${STATE_DIR}/mint.json")"

user="dogfood$(date +%s)"
claim_body="{\"username\":\"${user}\",\"pubkey\":\"age1dogfoodkey\",\"invite_code\":\"${invite}\"}"
claim_code="$(curl_json POST "${BASE_URL}/v1/claim" "" "${claim_body}" "${STATE_DIR}/claim.json")"
[[ "${claim_code}" == "201" ]] || { echo "claim failed: ${claim_code}" >&2; cat "${STATE_DIR}/claim.json" >&2; exit 1; }
api_key="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["api_key"])' "${STATE_DIR}/claim.json")"

me_code="$(curl_json GET "${BASE_URL}/v1/me/account" "${api_key}" "" "${STATE_DIR}/me.json")"
[[ "${me_code}" == "200" ]] || { echo "me/account failed: ${me_code}" >&2; cat "${STATE_DIR}/me.json" >&2; exit 1; }

rot_code="$(curl_json POST "${BASE_URL}/v1/me/api-key/rotate" "${api_key}" "" "${STATE_DIR}/rotate.json")"
[[ "${rot_code}" == "200" ]] || { echo "rotate failed: ${rot_code}" >&2; cat "${STATE_DIR}/rotate.json" >&2; exit 1; }

soft_delete_code="$(curl_json POST "${LOCAL_API}/v1/admin/accounts/${user}/soft-delete" "${SISUMAIL_ADMIN_TOKEN}" "" "${STATE_DIR}/soft_delete.json")"
[[ "${soft_delete_code}" == "200" ]] || { echo "soft-delete failed: ${soft_delete_code}" >&2; cat "${STATE_DIR}/soft_delete.json" >&2; exit 1; }

echo "smoke_ok user=${user}"
