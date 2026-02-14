#!/usr/bin/env bash
set -euo pipefail

host=""
user="root"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) host="$2"; shift 2 ;;
    --user) user="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${host}" ]]; then
  echo "usage: $0 --host <vps-ip> [--user root]" >&2
  exit 2
fi

target="${user}@${host}"
ssh_cmd=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${target}")

echo "[dns] delegate v6.<zone> on ${target}"
echo "[dns] expects on VPS:"
echo "  - /etc/sisumail.env has: HCLOUD_TOKEN, SISUMAIL_DNS_ZONE"

cat <<'PY' | "${ssh_cmd[@]}" "python3 -"
import json, sys, urllib.request, urllib.parse, urllib.error, subprocess

def sh(cmd):
  return subprocess.check_output(cmd, shell=True, text=True).strip()

def envfile(path):
  d={}
  try:
    with open(path, "r", encoding="utf-8") as f:
      for line in f:
        line=line.strip()
        if not line or line.startswith("#") or "=" not in line:
          continue
        k,v=line.split("=",1)
        d[k.strip()]=v.strip()
  except FileNotFoundError:
    return d
  return d

env = envfile("/etc/sisumail.env")
token = (env.get("HCLOUD_TOKEN","").strip() or env.get("HETZNER_CLOUD_TOKEN","").strip())
zone = env.get("SISUMAIL_DNS_ZONE","").strip().rstrip(".")
if not token:
  print("error: missing HCLOUD_TOKEN in /etc/sisumail.env", file=sys.stderr)
  sys.exit(2)
if not zone:
  print("error: missing SISUMAIL_DNS_ZONE in /etc/sisumail.env", file=sys.stderr)
  sys.exit(2)

def req(method, path, body=None):
  # Hetzner Cloud DNS API (Console). Sisumail uses this, not the deprecated dns.hetzner.com API.
  url = "https://api.hetzner.cloud/v1" + path
  data = None
  if body is not None:
    data = json.dumps(body).encode("utf-8")
  r = urllib.request.Request(url, data=data, method=method)
  r.add_header("Authorization", "Bearer " + token)
  r.add_header("Content-Type", "application/json")
  try:
    with urllib.request.urlopen(r, timeout=30) as resp:
      b = resp.read()
      if not b:
        return None
      return json.loads(b.decode("utf-8"))
  except urllib.error.HTTPError as e:
    msg = e.read().decode("utf-8", "replace")
    raise RuntimeError(f"http {e.code} {url}: {msg[:300]}")

def zone_id_by_name(name):
  q = urllib.parse.urlencode({"name": name})
  zs = (req("GET", "/zones?" + q) or {}).get("zones") or []
  for z in zs:
    if (z.get("name") or "").rstrip(".") == name:
      return str(z.get("id"))
  raise RuntimeError("zone not found in hetzner dns: %s" % name)

def list_records(zid):
  return (req("GET", f"/zones/{zid}/rrsets") or {}).get("rrsets") or []

def rr_name(fqdn, zone):
  fqdn = fqdn.strip().rstrip(".")
  if fqdn in ("", "@", zone):
    return "@"
  if fqdn.endswith("." + zone):
    fqdn = fqdn[:-(len(zone)+1)]
  return fqdn.lower()

def get_rrset(zid, name, typ):
  name = rr_name(name, zone)
  typ = typ.strip().upper()
  try:
    return (req("GET", f"/zones/{zid}/rrsets/{urllib.parse.quote(name)}/{typ}") or {}).get("rrset")
  except RuntimeError as e:
    if "http 404" in str(e):
      return None
    raise

def create_rrset(zid, name, typ, ttl, values):
  name = rr_name(name, zone)
  typ = typ.strip().upper()
  payload = {"name": name, "type": typ, "ttl": int(ttl), "records": [{"value": v} for v in values]}
  return req("POST", f"/zones/{zid}/rrsets", payload)

def set_records(zid, name, typ, values):
  name = rr_name(name, zone)
  typ = typ.strip().upper()
  payload = {"records": [{"value": v} for v in values]}
  return req("POST", f"/zones/{zid}/rrsets/{urllib.parse.quote(name)}/{typ}/actions/set_records", payload)

def upsert(zid, name, typ, ttl, value):
  rr = get_rrset(zid, name, typ)
  if rr is None:
    create_rrset(zid, name, typ, ttl, [value])
  else:
    set_records(zid, name, typ, [value])

def get_public_ipv6():
  # Prefer the routed primary /64's ::1, but actually detect what the box owns.
  # This returns something like "2a01:4f9:...::1".
  out = sh("ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1")
  return out.strip()

zid = zone_id_by_name(zone)
ipv6 = get_public_ipv6()
if not ipv6 or ":" not in ipv6:
  raise RuntimeError("unable to detect public ipv6 on VPS")

ns = f"ns1.{zone}"
delegate = f"v6.{zone}"

# Delegation + glue.
upsert(zid, delegate, "NS", 300, ns + ".")
upsert(zid, ns, "AAAA", 300, ipv6)

print("ok delegated", delegate, "NS", ns)
print("ok glue", ns, "AAAA", ipv6)
PY

echo "[dns] done"
