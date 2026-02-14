#!/usr/bin/env bash
set -euo pipefail

host=""
user="root"
strict=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) host="${2:-}"; shift 2 ;;
    --user) user="${2:-}"; shift 2 ;;
    --strict) strict=1; shift ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${host}" ]]; then
  echo "usage: $0 --host <ip-or-hostname> [--user root] [--strict]" >&2
  exit 2
fi

target="${user}@${host}"
ssh_cmd=(ssh -o BatchMode=yes -o ConnectTimeout=8 "${target}")

warns=0
fails=0

pass() { echo "PASS  $*"; }
warn() { echo "WARN  $*"; warns=$((warns + 1)); }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }

remote() {
  "${ssh_cmd[@]}" "$1"
}

echo "[audit] target=${target}"

# --- SSH hardening -----------------------------------------------------------
sshd_t="$(remote 'sshd -T 2>/dev/null || true')"
pass_auth="$(printf '%s\n' "${sshd_t}" | awk '/^passwordauthentication /{print $2}' | head -n1)"
root_login="$(printf '%s\n' "${sshd_t}" | awk '/^permitrootlogin /{print $2}' | head -n1)"
pubkey_auth="$(printf '%s\n' "${sshd_t}" | awk '/^pubkeyauthentication /{print $2}' | head -n1)"

if [[ "${pubkey_auth}" == "yes" ]]; then
  pass "ssh pubkey auth enabled"
else
  fail "ssh pubkey auth not enabled"
fi
if [[ "${pass_auth}" == "no" ]]; then
  pass "ssh password auth disabled"
else
  fail "ssh password auth enabled (${pass_auth:-unknown})"
fi
case "${root_login}" in
  no) pass "ssh root login disabled" ;;
  prohibit-password|without-password) warn "ssh root key login allowed (${root_login})" ;;
  *) warn "ssh root login policy unusual (${root_login:-unknown})" ;;
esac

# --- Systemd services --------------------------------------------------------
relay_state="$(remote 'systemctl is-active sisumail-relay 2>/dev/null || true')"
if [[ "${relay_state}" == "active" ]]; then
  pass "sisumail-relay.service active"
else
  fail "sisumail-relay.service not active (${relay_state:-unknown})"
fi

tier2_state="$(remote 'systemctl is-active sisumail-tier2 2>/dev/null || true')"
if [[ "${tier2_state}" == "active" ]]; then
  pass "sisumail-tier2.service active"
else
  fail "sisumail-tier2.service not active (${tier2_state:-unknown})"
fi

legacy_running="$(remote 'systemctl list-units --type=service --state=running --no-legend 2>/dev/null | sed -n "s/^\\(sisu-[^ ]*\\) .*/\\1/p" || true')"
if [[ -n "${legacy_running}" ]]; then
  warn "legacy sisu-* services still running (expected none)"
else
  pass "no legacy sisu-* services running"
fi

# Verify services are not running as root.
relay_user="$(remote 'systemctl show -p User --value sisumail-relay 2>/dev/null || true')"
relay_group="$(remote 'systemctl show -p Group --value sisumail-relay 2>/dev/null || true')"
if [[ -z "${relay_user}" || "${relay_user}" == "root" ]]; then
  warn "sisumail-relay runs as root (recommended: unprivileged user sisu)"
else
  pass "sisumail-relay runs as ${relay_user}:${relay_group:-?}"
fi
tier2_user="$(remote 'systemctl show -p User --value sisumail-tier2 2>/dev/null || true')"
tier2_group="$(remote 'systemctl show -p Group --value sisumail-tier2 2>/dev/null || true')"
if [[ -z "${tier2_user}" || "${tier2_user}" == "root" ]]; then
  warn "sisumail-tier2 runs as root (recommended: unprivileged user sisu with CAP_NET_BIND_SERVICE)"
else
  pass "sisumail-tier2 runs as ${tier2_user}:${tier2_group:-?}"
fi

# --- Port exposure -----------------------------------------------------------
# NOTE: use numeric ports (`-n`) so we don't have to match service names like "smtp".
listen="$(remote 'ss -tulpenHn 2>/dev/null || true')"
if printf '%s\n' "${listen}" | rg -n '0\.0\.0\.0:8787\b|:::8787\b|\*:8787\b' >/dev/null; then
  fail "legacy relay admin/API appears publicly bound on 8787"
else
  pass "no public 8787 listener detected"
fi
if printf '%s\n' "${listen}" | rg -n '0\.0\.0\.0:9090\b|:::9090\b|\*:9090\b' >/dev/null; then
  fail "observability endpoint appears publicly bound on 9090 (must stay loopback-only)"
else
  pass "observability endpoint not publicly bound on 9090"
fi
if printf '%s\n' "${listen}" | rg -n '127\.0\.0\.1:9090|\\[::1\\]:9090' >/dev/null; then
  pass "observability endpoint bound to loopback (9090)"
else
  warn "observability endpoint not found on loopback (expected 127.0.0.1:9090)"
fi

# Relay SSH gateway (clients connect here).
if printf '%s\n' "${listen}" | rg -n '0\.0\.0\.0:2222\b|:::2222\b|\*:2222\b' >/dev/null; then
  pass "relay SSH gateway bound publicly on 2222"
else
  fail "relay SSH gateway not publicly bound on 2222 (clients cannot connect)"
fi

# Tier 2 spool SMTP.
if printf '%s\n' "${listen}" | rg -n '0\.0\.0\.0:25\b|:::25\b|\*:25\b' >/dev/null; then
  pass "tier2 SMTP bound publicly on 25"
else
  fail "tier2 SMTP not publicly bound on 25"
fi

# Tier 1 proxy production mode is IPv6 :25 (AnyIP).
tier1_on_25=0
if printf '%s\n' "${listen}" | rg -n '\[::\]:25\b.*sisumail-relay|\*:25\b.*sisumail-relay' >/dev/null; then
  tier1_on_25=1
  pass "tier1 proxy bound on IPv6 :25 (production)"
fi

if [[ "${tier1_on_25}" == "1" ]]; then
  ndppd_state="$(remote 'systemctl is-active ndppd 2>/dev/null || true')"
  if [[ "${ndppd_state}" == "active" ]]; then
    pass "ndppd active (on-link /64 NDP proxy)"
  else
    warn "ndppd not active (ok only if /64 is L3-routed to host): state=${ndppd_state:-unknown}"
  fi
  ip_nonlocal="$(remote 'sysctl -n net.ipv6.ip_nonlocal_bind 2>/dev/null || true')"
  if [[ "${ip_nonlocal}" == "1" ]]; then
    pass "net.ipv6.ip_nonlocal_bind=1"
  else
    warn "net.ipv6.ip_nonlocal_bind not set to 1 (current=${ip_nonlocal:-unknown})"
  fi
else
  # Staging/dev: keep Tier 1 on loopback/high port until AnyIP is validated.
  if printf '%s\n' "${listen}" | rg -n '0\.0\.0\.0:2525\b|:::2525\b|\*:2525\b' >/dev/null; then
    warn "tier1 proxy bound publicly on 2525 (recommended: bind to 127.0.0.1:2525 until AnyIP/NDP is validated)"
  elif printf '%s\n' "${listen}" | rg -n '127\.0\.0\.1:2525|\\[::1\\]:2525' >/dev/null; then
    pass "tier1 proxy bound to loopback (2525)"
  else
    warn "tier1 proxy listener not found (2525)"
  fi
fi

# Well-known discovery doc is optional but recommended if this node is meant to be discoverable.
wk_public=0
wk_loopback=0
if printf '%s\n' "${listen}" | rg -n '0\.0\.0\.0:8080\b|:::8080\b|\*:8080\b' >/dev/null; then
  wk_public=1
fi
if printf '%s\n' "${listen}" | rg -n '127\.0\.0\.1:8080|\\[::1\\]:8080' >/dev/null; then
  wk_loopback=1
fi
caddy_state="$(remote 'systemctl is-active caddy 2>/dev/null || true')"
https_listen=0
if printf '%s\n' "${listen}" | rg -n '0\.0\.0\.0:443\b|:::443\b|\*:443\b' >/dev/null; then
  https_listen=1
fi
if [[ "${wk_public}" == "1" ]]; then
  pass "well-known HTTP listener bound publicly on 8080"
elif [[ "${wk_loopback}" == "1" && "${caddy_state}" == "active" && "${https_listen}" == "1" ]]; then
  pass "well-known served via HTTPS (caddy on 443, relay on loopback 8080)"
else
  warn "well-known not detected (expected either public 8080 or caddy on 443 proxying relay loopback 8080)"
fi

# --- Firewall ---------------------------------------------------------------
ufw_installed="$(remote 'command -v ufw >/dev/null 2>&1 && echo yes || echo no')"
if [[ "${ufw_installed}" != "yes" ]]; then
  warn "ufw not installed"
else
  ufw_status="$(remote 'ufw status verbose 2>/dev/null || true')"
  if printf '%s\n' "${ufw_status}" | rg -n 'Status: active' >/dev/null; then
    pass "ufw active"
  else
    warn "ufw not active"
  fi

  for p in 8787 9090 2525; do
    if printf '%s\n' "${ufw_status}" | rg -n "${p}/tcp.*ALLOW IN" >/dev/null; then
      fail "firewall exposes ${p}/tcp (expected blocked or loopback-only service)"
    else
      pass "firewall does not expose ${p}/tcp"
    fi
  done

  for p in 22 25 2222; do
    if printf '%s\n' "${ufw_status}" | rg -n "${p}/tcp.*ALLOW IN" >/dev/null; then
      pass "firewall allows ${p}/tcp"
    else
      warn "firewall does not explicitly allow ${p}/tcp (check if another firewall manages this)"
    fi
  done

  for p in 80 443; do
    if printf '%s\n' "${ufw_status}" | rg -n "${p}/tcp.*ALLOW IN" >/dev/null; then
      pass "firewall allows ${p}/tcp"
    else
      warn "firewall does not explicitly allow ${p}/tcp (ok if another firewall manages this)"
    fi
  done
fi

# --- Config and file permissions --------------------------------------------
env_stat="$(remote "stat -c '%a %U:%G' /etc/sisumail.env 2>/dev/null || true")"
if [[ "${env_stat}" =~ ^640\ root:sisu$ || "${env_stat}" =~ ^600\ root:root$ ]]; then
  pass "/etc/sisumail.env perms restricted (${env_stat})"
elif [[ -n "${env_stat}" ]]; then
  warn "/etc/sisumail.env perms unexpected (${env_stat})"
else
  fail "/etc/sisumail.env missing"
fi

wk_stat="$(remote "stat -c '%a %U:%G' /etc/sisumail/sisu-node.json 2>/dev/null || true")"
if [[ -n "${wk_stat}" ]]; then
  if [[ "${wk_stat}" =~ ^640\ root:sisu$ || "${wk_stat}" =~ ^644\ root:sisu$ || "${wk_stat}" =~ ^644\ root:root$ ]]; then
    pass "well-known doc file present (/etc/sisumail/sisu-node.json)"
  else
    warn "well-known doc file perms unexpected (${wk_stat})"
  fi
else
  warn "well-known doc file not found at /etc/sisumail/sisu-node.json"
fi

tier2_key_stat="$(remote "stat -c '%a %U:%G' /etc/sisumail/tls/spool.key 2>/dev/null || true")"
if [[ -n "${tier2_key_stat}" ]]; then
  if [[ "${tier2_key_stat}" =~ ^600\  || "${tier2_key_stat}" =~ ^640\  ]]; then
    pass "tier2 TLS key perms look restricted (${tier2_key_stat})"
  else
    warn "tier2 TLS key perms unexpected (${tier2_key_stat})"
  fi
else
  warn "tier2 TLS key not found at /etc/sisumail/tls/spool.key (ok if TLS is disabled/opportunistic without cert)"
fi

lib_stat="$(remote "stat -c '%a %U:%G' /var/lib/sisumail 2>/dev/null || true")"
if [[ "${lib_stat}" =~ ^700\ sisu:sisu$ ]]; then
  pass "/var/lib/sisumail perms restricted (${lib_stat})"
elif [[ -n "${lib_stat}" ]]; then
  warn "/var/lib/sisumail perms unexpected (${lib_stat})"
else
  warn "/var/lib/sisumail missing"
fi

spool_stat="$(remote "stat -c '%a %U:%G' /var/spool/sisumail 2>/dev/null || true")"
if [[ "${spool_stat}" =~ ^700\ sisu:sisu$ ]]; then
  pass "/var/spool/sisumail perms restricted (${spool_stat})"
elif [[ -n "${spool_stat}" ]]; then
  warn "/var/spool/sisumail perms unexpected (${spool_stat})"
else
  warn "/var/spool/sisumail missing"
fi

# --- Legacy layout drift -----------------------------------------------------
if remote 'test -d /opt/sisu-protocol'; then
  warn "legacy /opt/sisu-protocol still exists (expected removed)"
else
  pass "legacy /opt/sisu-protocol absent"
fi
if remote 'test -d /etc/sisu'; then
  warn "legacy /etc/sisu still exists (expected removed)"
else
  pass "legacy /etc/sisu absent"
fi

echo "[audit] summary fails=${fails} warns=${warns}"
if [[ ${fails} -gt 0 ]]; then
  exit 1
fi
if [[ ${strict} -eq 1 && ${warns} -gt 0 ]]; then
  exit 1
fi
