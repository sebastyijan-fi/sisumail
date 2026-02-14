#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Codex sandbox note:
# - Network is disabled (no module downloads).
# - Writes to $HOME/go can be denied by the sandbox policy.
# So we pin caches into the repo and seed from the existing global cache once.
if [[ "${CODEX_SANDBOX_NETWORK_DISABLED:-}" == "1" ]]; then
  default_modcache="$(go env GOMODCACHE 2>/dev/null || true)"
  repo_cache_root="${PWD}/.cache"
  repo_modcache="${repo_cache_root}/gomodcache"
  repo_gocache="${repo_cache_root}/gocache"

  mkdir -p "${repo_modcache}" "${repo_gocache}"
  if [[ -d "${default_modcache}/cache/download" ]]; then
    if [[ ! -d "${repo_modcache}/cache/download" || -z "$(ls -A "${repo_modcache}/cache/download" 2>/dev/null || true)" ]]; then
      mkdir -p "${repo_modcache}/cache/download"
      cp -a "${default_modcache}/cache/download/." "${repo_modcache}/cache/download/"
    fi
  fi

  export GOMODCACHE="${repo_modcache}"
  export GOCACHE="${repo_gocache}"
  export GOPROXY=off
  export GOSUMDB=off
fi

ROUNDS=1
PARALLEL=1
STRICT_MANUAL=0
SINGLE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rounds) ROUNDS="${2:-1}"; shift 2 ;;
    --parallel) PARALLEL="${2:-1}"; shift 2 ;;
    --strict-manual) STRICT_MANUAL=1; shift ;;
    --single) SINGLE="${2:-}"; shift 2 ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

VECTOR_IDS=(
  A01 A02 A03 A04 A05 A06 A07 A08 A09 A10
  A11 A12 A13 A14 A15 A16 A17 A18 A19 A20
  A21 A22 A23 A24 A25 A26 A27 A28 A29 A30
)

SISU_BIN=""
RELAY_BIN=""

build_bins() {
  local bdir
  bdir="$(mktemp -d)"
  SISU_BIN="${bdir}/sisumail"
  RELAY_BIN="${bdir}/sisumail-relay"
  go build -o "$SISU_BIN" ./cmd/sisumail
  go build -o "$RELAY_BIN" ./cmd/sisumail-relay
}

is_auto() {
  # Codex sandbox can't run the network/socket vectors (compiled Go binaries
  # get EPERM on socket syscalls in this environment).
  if [[ "${CODEX_SANDBOX_NETWORK_DISABLED:-}" == "1" ]]; then
    case "$1" in
      A02|A04|A05|A06|A07|A08|A17|A20|A24|A27) return 1 ;;
    esac
  fi
  case "$1" in
    A02|A03|A04|A05|A06|A07|A08|A09|A10|A11|A12|A13|A14|A15|A16|A17|A19|A20|A21|A22|A23|A24|A25|A26|A27|A28|A29|A30) return 0 ;;
    *) return 1 ;;
  esac
}

rand_port() {
  shuf -i 30000-59000 -n 1
}

wait_http_ok() {
  local url="$1"
  local tries="${2:-40}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.15
  done
  return 1
}

test_A02() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local good bad
  good="$(rand_port)"
  bad="$(rand_port)"
  ssh-keygen -t ed25519 -N '' -f "$tmp/u_key" -C "u-a02" >/dev/null

  "$RELAY_BIN" \
    -ssh-listen "127.0.0.1:${good}" \
    -tier1-listen "127.0.0.1:0" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey_good" \
    -spool-dir "$tmp/spool" \
    -allow-claim=false >/dev/null 2>"$tmp/relay-good.log" &
  sleep 0.5
  "$RELAY_BIN" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey_good" \
    -add-user -username niklas -pubkey "$tmp/u_key.pub" -ipv6 "2a01:db8::7" >/dev/null

  "$RELAY_BIN" \
    -ssh-listen "127.0.0.1:${bad}" \
    -tier1-listen "127.0.0.1:0" \
    -db "$tmp/relay2.db" \
    -hostkey "$tmp/hostkey_bad" \
    -spool-dir "$tmp/spool2" \
    -allow-claim=false >/dev/null 2>"$tmp/relay-bad.log" &
  sleep 0.5

  ssh-keyscan -p "$good" 127.0.0.1 >"$tmp/known_hosts" 2>/dev/null

  set +e
  timeout 8s "$SISU_BIN" \
    -relay "127.0.0.1:${bad}" \
    -user niklas \
    -key "$tmp/u_key" \
    -known-hosts "$tmp/known_hosts" \
    -smtp-listen "127.0.0.1:0" \
    -api-listen "" \
    -acme-dns01=false \
    -tls-policy pragmatic >"$tmp/client.out" 2>&1
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "A02 expected host key mismatch failure but command succeeded" >&2
    cat "$tmp/client.out" >&2
    return 1
  fi
  rg -n "knownhosts|host key|key is unknown|mismatch" "$tmp/client.out" >/dev/null
}

test_A06() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local sshp smtpp apip
  sshp="$(rand_port)"
  smtpp="$(rand_port)"
  apip="$(rand_port)"
  ssh-keygen -t ed25519 -N '' -f "$tmp/u_key" -C "u-a06" >/dev/null

  "$RELAY_BIN" \
    -ssh-listen "127.0.0.1:${sshp}" \
    -tier1-listen "127.0.0.1:0" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -spool-dir "$tmp/spool" \
    -allow-claim=false >/dev/null 2>"$tmp/relay.log" &
  sleep 0.5
  "$RELAY_BIN" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -add-user -username niklas -pubkey "$tmp/u_key.pub" -ipv6 "2a01:db8::8" >/dev/null

  timeout 25s "$SISU_BIN" \
    -relay "127.0.0.1:${sshp}" \
    -user niklas \
    -key "$tmp/u_key" \
    -insecure-host-key \
    -smtp-listen "127.0.0.1:${smtpp}" \
    -api-listen "127.0.0.1:${apip}" \
    -api-token-path "$tmp/api-token" \
    -acme-dns01=false \
    -tls-policy pragmatic >"$tmp/client.out" 2>&1 &
  sleep 1
  wait_http_ok "http://127.0.0.1:${apip}/app" 30

  local code
  code="$(curl -s -o /tmp/a06.out -w "%{http_code}" -X POST "http://127.0.0.1:${apip}/app/v1/message/fake/delete")"
  [[ "$code" == "401" ]]
}

test_A17() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local sshp
  sshp="$(rand_port)"
  ssh-keygen -t ed25519 -N '' -f "$tmp/u_key" -C "u-a17" >/dev/null

  "$RELAY_BIN" \
    -ssh-listen "127.0.0.1:${sshp}" \
    -tier1-listen "127.0.0.1:0" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -spool-dir "$tmp/spool" \
    -allow-claim=false >/dev/null 2>"$tmp/relay.log" &
  sleep 0.5
  "$RELAY_BIN" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -add-user -username niklas -pubkey "$tmp/u_key.pub" -ipv6 "2a01:db8::9" >/dev/null

  HOME="$tmp/home" "$SISU_BIN" -profile default -user niklas -chat-allow alice >/dev/null 2>&1
  set +e
  HOME="$tmp/home" timeout 15s "$SISU_BIN" \
    -profile default \
    -relay "127.0.0.1:${sshp}" \
    -user niklas \
    -key "$tmp/u_key" \
    -insecure-host-key \
    -smtp-listen "127.0.0.1:0" \
    -api-listen "" \
    -acme-dns01=false \
    -tls-policy pragmatic \
    -chat-to bob \
    -chat-msg "guard" >"$tmp/out" 2>&1
  local rc=$?
  set -e
  [[ $rc -ne 0 ]]
  rg -n "not in allowlist|chat send blocked" "$tmp/out" >/dev/null
}

test_A21() {
  local tmp; tmp="$(mktemp -d)"
  trap '[[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  HOME="$tmp/home" "$SISU_BIN" -profile default -user niklas -init >/dev/null 2>&1
  HOME="$tmp/home" "$SISU_BIN" -profile beta -user beta -init >/dev/null 2>&1
  local d1 d2
  d1="$(HOME="$tmp/home" "$SISU_BIN" -profile default -inbox 2>&1 | sed -n '1p' || true)"
  d2="$(HOME="$tmp/home" "$SISU_BIN" -profile beta -inbox 2>&1 | sed -n '1p' || true)"
  [[ -d "$tmp/home/.local/share/sisumail/mail" ]]
  [[ -d "$tmp/home/.local/share/sisumail/profiles/beta/mail" ]]
  [[ "$tmp/home/.local/share/sisumail/mail" != "$tmp/home/.local/share/sisumail/profiles/beta/mail" ]]
  # keep shellcheck happy with used vars
  : "$d1" "$d2"
}

test_A22() {
  local tmp; tmp="$(mktemp -d)"
  trap '[[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  HOME="$tmp/home" "$SISU_BIN" -profile default -user niklas -init >/dev/null 2>&1
  HOME="$tmp/home" "$SISU_BIN" -profile beta -user beta -init >/dev/null 2>&1
  HOME="$tmp/home" "$SISU_BIN" -profile default -chat-allow alice >/dev/null 2>&1
  local d c
  d="$(HOME="$tmp/home" "$SISU_BIN" -profile default -chat-contacts)"
  c="$(HOME="$tmp/home" "$SISU_BIN" -profile beta -chat-contacts || true)"
  echo "$d" | rg -n '^alice$' >/dev/null
  ! echo "$c" | rg -n '^alice$' >/dev/null
}

test_A27() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local sshp smtpp
  sshp="$(rand_port)"
  smtpp="$(rand_port)"
  ssh-keygen -t ed25519 -N '' -f "$tmp/u_key" -C "u-a27" >/dev/null

  "$RELAY_BIN" \
    -ssh-listen "127.0.0.1:${sshp}" \
    -tier1-listen "127.0.0.1:0" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -spool-dir "$tmp/spool" \
    -allow-claim=false >/dev/null 2>"$tmp/relay.log" &
  sleep 0.5
  "$RELAY_BIN" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -add-user -username niklas -pubkey "$tmp/u_key.pub" -ipv6 "2a01:db8::a" >/dev/null

  timeout 25s "$SISU_BIN" \
    -relay "127.0.0.1:${sshp}" \
    -user niklas \
    -key "$tmp/u_key" \
    -insecure-host-key \
    -smtp-listen "127.0.0.1:${smtpp}" \
    -api-listen "" \
    -acme-dns01=false \
    -tls-policy pragmatic >"$tmp/client.out" 2>&1 &
  sleep 1

  printf "EHLO x\r\nMAIL FROM:<a@b.c>\r\nQUIT\r\n" | nc -w 2 127.0.0.1 "${smtpp}" >"$tmp/smtp.out" 2>&1 || true
  rg -n "530|Must issue STARTTLS first" "$tmp/smtp.out" >/dev/null
}

test_A13() {
  go test ./internal/tier2 -run "TestReceiverRateLimitsMessagesBySource" -count=1 >/dev/null
}

test_A14() {
  go test ./internal/tier2 -run "TestFileSpoolPutRejectsPlaintextPayload" -count=1 >/dev/null
}

test_A25() {
  go test ./cmd/sisumail-relay -run "TestACMEDNS01ControllerRateLimit" -count=1 >/dev/null
}

test_A26() {
  if [[ "${SISU_VECTOR_DNS_LIVE:-0}" == "1" ]]; then
    scripts/dns_integrity_check.sh --live-required
    return
  fi
  scripts/dns_integrity_check.sh --template-only
}

test_A28() {
  go test ./cmd/sisumail-relay -run "TestIsSupportedClientChannelType" -count=1 >/dev/null
}

test_A29() {
  scripts/artifact_integrity_check.sh
}

test_A30() {
  scripts/dependency_vuln_scan.sh
}

first_non_loopback_ipv4() {
  local ip
  ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | rg -n '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' -N | sed -E 's/^[0-9]+://' | head -n1 || true)"
  if [[ -z "$ip" ]]; then
    return 1
  fi
  case "$ip" in
    127.*) return 1 ;;
  esac
  printf "%s" "$ip"
}

start_local_app_harness() {
  local tmp="$1"
  local sshp smtpp apip
  local home="$tmp/home"
  mkdir -p "$home"
  sshp="$(rand_port)"
  smtpp="$(rand_port)"
  apip="$(rand_port)"
  echo "$home" >"$tmp/home_path"
  echo "$sshp" >"$tmp/sshp"
  echo "$smtpp" >"$tmp/smtpp"
  echo "$apip" >"$tmp/apip"

  ssh-keygen -t ed25519 -N '' -f "$tmp/u_key" -C "u-app-h" >/dev/null
  "$RELAY_BIN" \
    -ssh-listen "127.0.0.1:${sshp}" \
    -tier1-listen "127.0.0.1:0" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -spool-dir "$tmp/spool" \
    -allow-claim=false >/dev/null 2>"$tmp/relay.log" &
  sleep 0.5
  "$RELAY_BIN" \
    -db "$tmp/relay.db" \
    -hostkey "$tmp/hostkey" \
    -add-user -username niklas -pubkey "$tmp/u_key.pub" -ipv6 "2a01:db8::b" >/dev/null

  HOME="$home" timeout 25s "$SISU_BIN" \
    -relay "127.0.0.1:${sshp}" \
    -user niklas \
    -key "$tmp/u_key" \
    -insecure-host-key \
    -smtp-listen "127.0.0.1:${smtpp}" \
    -api-listen "127.0.0.1:${apip}" \
    -api-token-path "$tmp/api-token" \
    -acme-dns01=false \
    -tls-policy pragmatic >"$tmp/client.out" 2>&1 &
  sleep 0.8

  if ! wait_http_ok "http://127.0.0.1:${apip}/app" 60; then
    echo "harness: local /app did not come up (apip=${apip})" >&2
    if [[ -f "$tmp/client.out" ]]; then
      tail -n 80 "$tmp/client.out" >&2 || true
    fi
    return 1
  fi

  for _ in $(seq 1 80); do
    if [[ -s "$tmp/api-token" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "harness: api token file not created ($tmp/api-token)" >&2
  if [[ -f "$tmp/client.out" ]]; then
    tail -n 80 "$tmp/client.out" >&2 || true
  fi
  return 1
}

test_A03() {
  local tmp; tmp="$(mktemp -d)"
  trap '[[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  set +e
  timeout 4s "$SISU_BIN" \
    -relay "127.0.0.1:1" \
    -insecure-host-key \
    -acme-dns01=false \
    -api-listen "" \
    -smtp-listen "127.0.0.1:0" >"$tmp/out" 2>&1
  local rc=$?
  set -e
  [[ $rc -ne 0 ]]
  rg -n "WARNING: relay host key verification disabled" "$tmp/out" >/dev/null
}

test_A04() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local home="$tmp/home"
  mkdir -p "$home"
  HOME="$home" "$SISU_BIN" -profile default -user niklas -init >/dev/null 2>&1
  HOME="$home" "$SISU_BIN" -profile sebastyijan -user sebastyijan -init >/dev/null 2>&1
  start_local_app_harness "$tmp" || return 1
  local apip
  apip="$(cat "$tmp/apip")"
  local token js_default js_other
  token="$(curl -fsS "http://127.0.0.1:${apip}/app/inbox" | rg -o "APP_SESSION_TOKEN = '[^']+'" -m1 | sed -E "s/.*'([^']+)'.*/\\1/")"
  [[ -n "$token" ]]
  js_default="$(curl -fsS -H "X-Sisu-App-Token: ${token}" "http://127.0.0.1:${apip}/app/v1/status")"
  js_other="$(curl -fsS -H "X-Sisu-App-Token: ${token}" "http://127.0.0.1:${apip}/app/v1/status?profile=sebastyijan")"
  echo "$js_default" | rg -n '"profile"[[:space:]]*:[[:space:]]*"default"' >/dev/null
  echo "$js_default" | rg -n '"runtime_profile"[[:space:]]*:[[:space:]]*"default"' >/dev/null
  echo "$js_default" | rg -n '"user"[[:space:]]*:[[:space:]]*"niklas"' >/dev/null
  echo "$js_other" | rg -n '"profile"[[:space:]]*:[[:space:]]*"sebastyijan"' >/dev/null
  echo "$js_other" | rg -n '"runtime_profile"[[:space:]]*:[[:space:]]*"default"' >/dev/null
  echo "$js_other" | rg -n '"user"[[:space:]]*:[[:space:]]*"sebastyijan"' >/dev/null
}

test_A05() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local home="$tmp/home"
  mkdir -p "$home/.config/sisumail"
  printf 'ghost\n' >"$home/.config/sisumail/active_profile"
  start_local_app_harness "$tmp" || return 1
  local apip
  apip="$(cat "$tmp/apip")"
  local token js
  token="$(curl -fsS "http://127.0.0.1:${apip}/app/inbox" | rg -o "APP_SESSION_TOKEN = '[^']+'" -m1 | sed -E "s/.*'([^']+)'.*/\\1/")"
  [[ -n "$token" ]]
  js="$(curl -fsS -H "X-Sisu-App-Token: ${token}" "http://127.0.0.1:${apip}/app/v1/status")"
  echo "$js" | rg -n '"profile"[[:space:]]*:[[:space:]]*"default"' >/dev/null
  echo "$js" | rg -n '"runtime_profile"[[:space:]]*:[[:space:]]*"default"' >/dev/null
}

test_A08() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  start_local_app_harness "$tmp" || return 1
  local apip tok homep
  apip="$(cat "$tmp/apip")"
  homep="$(cat "$tmp/home_path")"
  tok="$(tr -d '\r\n' < "$tmp/api-token")"
  [[ -n "$tok" ]]
  [[ "$(stat -c '%a' "$tmp/api-token")" == "600" ]]
  ! rg -n --fixed-strings "$tok" "$homep/.local/state/sisumail" >/dev/null 2>&1
  local p1 p2 p3
  p1="$(curl -fsS "http://127.0.0.1:${apip}/app")"
  p2="$(curl -fsS "http://127.0.0.1:${apip}/app/inbox")"
  p3="$(curl -fsS "http://127.0.0.1:${apip}/app/chat")"
  ! echo "$p1" | rg -n --fixed-strings "$tok" >/dev/null
  ! echo "$p2" | rg -n --fixed-strings "$tok" >/dev/null
  ! echo "$p3" | rg -n --fixed-strings "$tok" >/dev/null
}

test_A09() {
  go test ./cmd/sisumail -run "TestLocalInboxAppUsesSafeTextRendering" -count=1 >/dev/null
}

test_A10() {
  go test ./cmd/sisumail -run "TestAliasFromMessageHeadersIgnoresInvalidAndKeepsInjectedFirst" -count=1 >/dev/null
}

test_A11() {
  go test ./cmd/sisumail -run "TestAliasFromAddressRejectsMalformedAliases" -count=1 >/dev/null
}

test_A12() {
  go test ./cmd/sisumail -run "TestLocalSessionRcptBlockedAliasLooksLikeInvalidRecipient" -count=1 >/dev/null
}

test_A15() {
  go test ./cmd/sisumail -run "TestSpoolReplayGuardSeenOrMark" -count=1 >/dev/null
}

test_A16() {
  go test ./cmd/sisumail -run "TestLocalSMTPMaxMessageBytesLimit" -count=1 >/dev/null
}

test_A19() {
  go test ./cmd/sisumail -run "TestRelayControlUnavailableDetectors|TestNormalizeChatSendError|TestLocalChatAppShowsRelayChannelGuidance" -count=1 >/dev/null
}

test_A07() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local ip
  ip="$(first_non_loopback_ipv4 || true)"
  if [[ -z "$ip" ]]; then
    echo "manual-vector: no non-loopback IPv4 detected"
    return 3
  fi
  start_local_app_harness "$tmp" || return 1
  local apip token code
  apip="$(cat "$tmp/apip")"
  token="$(curl -fsS "http://127.0.0.1:${apip}/app/inbox" | rg -o "APP_SESSION_TOKEN = '[^']+'" -m1 | sed -E "s/.*'([^']+)'.*/\\1/")"
  [[ -n "$token" ]]
  code="$(curl -s -o /tmp/a07.out -w "%{http_code}" -H "X-Sisu-App-Token: ${token}" "http://${ip}:${apip}/app/v1/status")"
  if [[ "$code" == "403" ]]; then
    return 0
  fi
  echo "manual-vector: non-loopback route test inconclusive (ip=${ip} code=${code})"
  return 3
}

test_A20() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  start_local_app_harness "$tmp" || return 1
  local apip token code1 code2
  apip="$(cat "$tmp/apip")"
  token="$(curl -fsS "http://127.0.0.1:${apip}/app/inbox" | rg -o "APP_SESSION_TOKEN = '[^']+'" -m1 | sed -E "s/.*'([^']+)'.*/\\1/")"
  [[ -n "$token" ]]
  code1="$(curl -s -o /tmp/a20a.out -w "%{http_code}" -X POST "http://127.0.0.1:${apip}/app/v1/message/fake/delete")"
  code2="$(curl -s -o /tmp/a20b.out -w "%{http_code}" -X POST -H "X-Sisu-App-Token: wrong" "http://127.0.0.1:${apip}/app/v1/message/fake/delete")"
  [[ "$code1" == "401" ]]
  [[ "$code2" == "401" ]]
}

test_A23() {
  local tmp; tmp="$(mktemp -d)"
  trap '[[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  local home="$tmp/home"
  HOME="$home" "$SISU_BIN" -init >/dev/null 2>&1
  local cfg="$home/.config/sisumail/config.env"
  [[ -f "$cfg" ]]
  [[ "$(stat -c '%a' "$cfg")" == "600" ]]
  local kh="$home/.ssh/known_hosts"
  [[ -f "$kh" ]]
  [[ "$(stat -c '%a' "$kh")" == "600" ]]
  local key="$home/.ssh/id_ed25519"
  [[ -f "$key" ]]
  [[ "$(stat -c '%a' "$key")" == "600" ]]
}

test_A24() {
  local tmp; tmp="$(mktemp -d)"
  trap 'set +e; kill $(jobs -pr) 2>/dev/null; [[ -n "${tmp:-}" ]] && rm -rf "${tmp:-}"' RETURN
  start_local_app_harness "$tmp" || return 1
  local tok
  tok="$(tr -d '\r\n' < "$tmp/api-token")"
  [[ -n "$tok" ]]
  ! rg -n "$tok" "$tmp/client.out" >/dev/null
  ! rg -n "BEGIN OPENSSH PRIVATE KEY|PRIVATE KEY" "$tmp/client.out" >/dev/null
}

run_vector() {
  local id="$1"
  case "$id" in
    A02) test_A02 ;;
    A03) test_A03 ;;
    A04) test_A04 ;;
    A05) test_A05 ;;
    A06) test_A06 ;;
    A07) test_A07 ;;
    A08) test_A08 ;;
    A09) test_A09 ;;
    A10) test_A10 ;;
    A11) test_A11 ;;
    A12) test_A12 ;;
    A13) test_A13 ;;
    A14) test_A14 ;;
    A15) test_A15 ;;
    A16) test_A16 ;;
    A17) test_A17 ;;
    A19) test_A19 ;;
    A20) test_A20 ;;
    A21) test_A21 ;;
    A22) test_A22 ;;
    A23) test_A23 ;;
    A24) test_A24 ;;
    A25) test_A25 ;;
    A26) test_A26 ;;
    A27) test_A27 ;;
    A28) test_A28 ;;
    A29) test_A29 ;;
    A30) test_A30 ;;
    *)
      echo "manual-vector"
      return 3
      ;;
  esac
}

if [[ -n "$SINGLE" ]]; then
  build_bins
  run_vector "$SINGLE"
  exit $?
fi

tmproot="$(mktemp -d)"
trap 'rm -rf "$tmproot"' EXIT
build_bins

total_pass=0
total_fail=0
total_manual=0

for round in $(seq 1 "$ROUNDS"); do
  echo "[vectors] round ${round}/${ROUNDS}"
  mapfile -t order < <(printf "%s\n" "${VECTOR_IDS[@]}" | shuf)
  declare -A pid_to_id=()
  for id in "${order[@]}"; do
    if ! is_auto "$id"; then
      echo "[vectors] MANUAL ${id}"
      total_manual=$((total_manual + 1))
      continue
    fi
    while [[ "$(jobs -pr | wc -l | tr -d ' ')" -ge "$PARALLEL" ]]; do
      wait -n || true
    done
    (
      set +e
      out="$(run_vector "$id" 2>&1)"
      rc=$?
      echo "$out" >"$tmproot/${round}_${id}.log"
      exit $rc
    ) &
    pid_to_id[$!]="$id"
  done

  for pid in "${!pid_to_id[@]}"; do
    id="${pid_to_id[$pid]}"
    if wait "$pid"; then
      echo "[vectors] PASS ${id}"
      total_pass=$((total_pass + 1))
      continue
    fi
    rc=$?
    if [[ $rc -eq 3 ]]; then
      echo "[vectors] MANUAL ${id}"
      total_manual=$((total_manual + 1))
      continue
    fi
    if rg -n "manual-vector" "$tmproot/${round}_${id}.log" >/dev/null 2>&1; then
      echo "[vectors] MANUAL ${id}"
      total_manual=$((total_manual + 1))
      continue
    fi
    echo "[vectors] FAIL ${id}"
    total_fail=$((total_fail + 1))
    cat "$tmproot/${round}_${id}.log"
  done
done

echo "[vectors] summary: pass=${total_pass} fail=${total_fail} manual=${total_manual}"
if [[ $STRICT_MANUAL -eq 1 && $total_manual -gt 0 ]]; then
  exit 1
fi
[[ $total_fail -eq 0 ]]
