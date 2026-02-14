#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host=""
user="root"
domain="sisumail.fi"
web_root="/var/www/sisumail"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) host="${2:-}"; shift 2 ;;
    --user) user="${2:-}"; shift 2 ;;
    --domain) domain="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage:
  scripts/vps_setup_web.sh --host <ip-or-hostname> [--user root] [--domain sisumail.fi]

What it does (remote):
  - Installs Caddy (Ubuntu package).
  - Serves a simple landing page on https://<domain>/ and a stub on https://spool.<domain>/.
  - Serves https://<domain>/.well-known/sisu-node by reverse-proxying the relay's well-known HTTP listener.
  - Locks the relay well-known listener to 127.0.0.1:8080 and removes public UFW exposure for 8080.
  - Publishes /install.sh (copy of scripts/install_client.sh).

Notes:
  - HTTPS certificates require <domain> DNS A/AAAA to point to this VPS before ACME can succeed.
  - This script does NOT edit DNS records (token-free by design).
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

remote() {
  "${ssh_cmd[@]}" "$1"
}

echo "[web] target=${target} domain=${domain}"

echo "[web] install caddy"
remote "DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y caddy >/dev/null"

echo "[web] web root + landing page"
remote "install -d -m 0755 '${web_root}'"
cat deploy/web/index.html | "${ssh_cmd[@]}" "cat > '${web_root}/index.html' && chmod 0644 '${web_root}/index.html'"

echo "[web] publish install script (/install.sh)"
cat scripts/install_client.sh | "${ssh_cmd[@]}" "cat > '${web_root}/install.sh' && chmod 0755 '${web_root}/install.sh'"

echo "[web] caddy config"
cat <<EOF | "${ssh_cmd[@]}" "cat > /etc/caddy/Caddyfile"
{
  email admin@${domain}
}

${domain} {
  encode zstd gzip
  root * ${web_root}
  file_server

  @wk path /.well-known/sisu-node
  handle @wk {
    reverse_proxy 127.0.0.1:8080
  }
}

spool.${domain} {
  respond "ok" 200
}
EOF

echo "[web] lock relay well-known to loopback"
remote "if grep -q '^SISUMAIL_WELL_KNOWN_LISTEN=' /etc/sisumail.env 2>/dev/null; then
  sed -i 's/^SISUMAIL_WELL_KNOWN_LISTEN=.*/SISUMAIL_WELL_KNOWN_LISTEN=127.0.0.1:8080/' /etc/sisumail.env
else
  printf '\nSISUMAIL_WELL_KNOWN_LISTEN=127.0.0.1:8080\n' >> /etc/sisumail.env
fi"
remote "systemctl restart sisumail-relay"

echo "[web] firewall: allow 80/443 and remove 8080"
remote "ufw allow 80/tcp >/dev/null || true
ufw allow 443/tcp >/dev/null || true
ufw delete allow 8080/tcp >/dev/null 2>&1 || true
ufw status | sed -n '1,120p'"

echo "[web] start caddy"
remote "systemctl enable --now caddy >/dev/null
systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null
systemctl is-active caddy >/dev/null
curl -fsS -H 'Host: ${domain}' http://127.0.0.1/ >/dev/null
curl -fsS http://127.0.0.1:8080/.well-known/sisu-node >/dev/null
echo ok"

echo "[web] done"

