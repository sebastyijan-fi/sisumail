#!/usr/bin/env bash
set -euo pipefail

host=""
user="root"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) host="${2:-}"; shift 2 ;;
    --user) user="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage:
  scripts/vps_dns_cutover.sh --host <ip-or-hostname> [--user root]

What it does (remote, using Hetzner Console DNS via HCLOUD_TOKEN from /etc/sisumail.env):
  - Sets zone root A/AAAA to this VPS (IPv4 + IPv6).
  - Sets spool.<zone> A to this VPS (IPv4).
  - Removes spool.<zone> AAAA (important when Tier 1 is IPv6 :25 and Tier 2 is IPv4 :25).

Requirements on the VPS:
  - /etc/sisumail.env has: HCLOUD_TOKEN, SISUMAIL_DNS_ZONE
  - python3 is installed

This script never prints the token.
EOF
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${host}" ]]; then
  echo "error: --host is required" >&2
  exit 2
fi

target="${user}@${host}"
ssh_cmd=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no "${target}")

echo "[dns] target=${target}"

cat <<'PY' | "${ssh_cmd[@]}" "python3 -"
import json, subprocess, sys, urllib.request, urllib.parse

def sh(cmd):
  return subprocess.check_output(cmd, shell=True, text=True).strip()

def envfile(path):
  out={}
  try:
    with open(path, "r", encoding="utf-8") as f:
      for line in f:
        line=line.strip()
        if not line or line.startswith("#") or "=" not in line:
          continue
        k,v=line.split("=",1)
        out[k.strip()]=v.strip()
  except FileNotFoundError:
    pass
  return out

env = envfile("/etc/sisumail.env")
token = (env.get("HCLOUD_TOKEN","").strip() or env.get("HETZNER_CLOUD_TOKEN","").strip())
zone = env.get("SISUMAIL_DNS_ZONE","").strip().rstrip(".")
if not token:
  print("error: missing HCLOUD_TOKEN in /etc/sisumail.env", file=sys.stderr)
  sys.exit(2)
if not zone:
  print("error: missing SISUMAIL_DNS_ZONE in /etc/sisumail.env", file=sys.stderr)
  sys.exit(2)

ipv4 = sh("ip -4 addr show dev eth0 | sed -n \"s/.*inet \\([^/ ]\\+\\).*/\\1/p\" | head -n1")
ipv6 = sh("ip -6 addr show dev eth0 scope global | sed -n \"s/.*inet6 \\([^/ ]\\+\\).*/\\1/p\" | head -n1")
if not ipv4 or not ipv6:
  print(f"error: failed to detect eth0 public IPs (v4={ipv4!r} v6={ipv6!r})", file=sys.stderr)
  sys.exit(2)

base = "https://api.hetzner.cloud/v1"

def req(method, path, body=None):
  url = base + path
  data = None
  headers = {"Authorization": "Bearer " + token}
  if body is not None:
    data = json.dumps(body).encode("utf-8")
    headers["Content-Type"] = "application/json"
  r = urllib.request.Request(url, data=data, headers=headers, method=method)
  try:
    with urllib.request.urlopen(r, timeout=25) as resp:
      b = resp.read()
      if not b:
        return None
      return json.loads(b.decode("utf-8"))
  except urllib.error.HTTPError as e:
    msg = e.read().decode("utf-8", "replace")
    raise RuntimeError(f"http {e.code} {url}: {msg[:300]}")

def zone_id_by_name(name):
  q = urllib.parse.urlencode({"name": name})
  data = req("GET", "/zones?" + q)
  zs = (data or {}).get("zones") or []
  for z in zs:
    if (z.get("name") or "").rstrip(".") == name.rstrip("."):
      return str(z.get("id"))
  raise RuntimeError("zone not found: " + name)

def rr_name(fqdn):
  fqdn = fqdn.strip().rstrip(".")
  if fqdn in ("", "@", zone):
    return "@"
  if fqdn.endswith("." + zone):
    fqdn = fqdn[:-(len(zone)+1)]
  return fqdn.lower()

def get_rrset(zid, name, typ):
  name = rr_name(name)
  typ = typ.strip().upper()
  try:
    data = req("GET", f"/zones/{zid}/rrsets/{name}/{typ}")
    return (data or {}).get("rrset")
  except RuntimeError as e:
    if "http 404" in str(e):
      return None
    raise

def set_records(zid, name, typ, values):
  name = rr_name(name)
  typ = typ.strip().upper()
  payload = {"records": [{"value": v} for v in values]}
  return req("POST", f"/zones/{zid}/rrsets/{name}/{typ}/actions/set_records", payload)

def create_rrset(zid, name, typ, ttl, values):
  name = rr_name(name)
  typ = typ.strip().upper()
  payload = {"name": name, "type": typ, "ttl": int(ttl), "records": [{"value": v} for v in values]}
  return req("POST", f"/zones/{zid}/rrsets", payload)

def upsert_rrset(zid, name, typ, ttl, values):
  rr = get_rrset(zid, name, typ)
  if rr is None:
    create_rrset(zid, name, typ, ttl, values)
  else:
    set_records(zid, name, typ, values)

def remove_rrset(zid, name, typ):
  rr = get_rrset(zid, name, typ)
  if not rr:
    return
  recs = rr.get("records") or []
  values = [r.get("value","").strip() for r in recs if (r.get("value") or "").strip()]
  if not values:
    return
  payload = {"records": [{"value": v} for v in values]}
  req("POST", f"/zones/{zid}/rrsets/{rr_name(name)}/{typ.strip().upper()}/actions/remove_records", payload)

zid = zone_id_by_name(zone)

upsert_rrset(zid, zone, "A", 60, [ipv4])
upsert_rrset(zid, zone, "AAAA", 60, [ipv6])

upsert_rrset(zid, "spool."+zone, "A", 60, [ipv4])
remove_rrset(zid, "spool."+zone, "AAAA")

print("ok")
print("zone", zone)
print("root A", ipv4)
print("root AAAA", ipv6)
print("spool A", ipv4)
print("spool AAAA", "removed")
PY

echo "[dns] done"
