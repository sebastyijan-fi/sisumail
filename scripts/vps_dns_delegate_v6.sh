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
import json, os, sys, urllib.request, urllib.parse, subprocess

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
token = env.get("HCLOUD_TOKEN","").strip()
zone = env.get("SISUMAIL_DNS_ZONE","").strip().rstrip(".")
if not token:
  print("error: missing HCLOUD_TOKEN in /etc/sisumail.env", file=sys.stderr)
  sys.exit(2)
if not zone:
  print("error: missing SISUMAIL_DNS_ZONE in /etc/sisumail.env", file=sys.stderr)
  sys.exit(2)

def req(method, path, body=None):
  url = "https://dns.hetzner.com/api/v1" + path
  data = None
  if body is not None:
    data = json.dumps(body).encode("utf-8")
  r = urllib.request.Request(url, data=data, method=method)
  r.add_header("Auth-API-Token", token)
  r.add_header("Content-Type", "application/json")
  with urllib.request.urlopen(r, timeout=30) as resp:
    b = resp.read()
    if not b:
      return None
    return json.loads(b.decode("utf-8"))

def zone_id_by_name(name):
  zs = req("GET", "/zones")["zones"]
  for z in zs:
    if z["name"].rstrip(".") == name:
      return z["id"]
  raise RuntimeError("zone not found in hetzner dns: %s" % name)

def list_records(zid):
  return req("GET", f"/records?zone_id={urllib.parse.quote(zid)}")["records"]

def upsert(zid, name, typ, ttl, value):
  name = name.rstrip(".")
  existing = [r for r in list_records(zid) if r["name"].rstrip(".")==name and r["type"]==typ]
  if existing:
    rid = existing[0]["id"]
    req("PUT", f"/records/{rid}", {"value": value, "ttl": ttl, "type": typ, "name": name, "zone_id": zid})
    # Delete any extras to avoid provider-side weirdness.
    for r in existing[1:]:
      req("DELETE", f"/records/{r['id']}")
  else:
    req("POST", "/records", {"value": value, "ttl": ttl, "type": typ, "name": name, "zone_id": zid})

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

