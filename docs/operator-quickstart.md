# Relay Operator Quickstart (VPS)

This is a **relay operator** guide: you run the infrastructure for a domain (DNS + IPv6 AnyIP + Tier 1 proxy + SSH gateway, and later Tier 2 spool).

If you only want to run a personal always-on node that connects to an existing relay, you do **not** need this doc (node mode docs not written yet).

## Current Reality (Read First)

Working today:
- Tier 1 proxy + SSH gateway (dev ports by default).
- Identity registry (SQLite) and first-come claim semantics.
- Hetzner Console DNS (Cloud API) provisioning exists and is wired into the relay **if** env vars are present.

Not production-ready yet:
- Full observability stack (metrics endpoint, alerting policy, SLO dashboards) is not complete.
- Safe port-22 migration plan (product SSH on `:22` while keeping admin access) is not finalized.

## Prereqs

- A VPS with:
  - 1 static IPv4
  - a routed IPv6 /64 (preferred) or a provider-supported equivalent
- A domain you control (example: `sisumail.fi`)
- DNS zone managed in **Hetzner Console DNS** (Zones API via Hetzner Cloud API token).

## 1) Provision DNS (Split MX Model)

Per user `<u>` you will publish:

- `MX 10 v6.<u>.<zone>` (Tier 1)
- `MX 20 spool.<zone>` (Tier 2 fallback)
- `AAAA v6.<u>.<zone> -> <unique per-user IPv6>`

Templates: see `docs/dns-records.md`.

## 2) Enable IPv6 AnyIP (Tier 1 ingress)

Tier 1 requires the relay to accept inbound SMTP on **many** destination IPv6 addresses from your /64.

Recommended Linux primitive (AnyIP):

```bash
ip -6 route add local <relay_ipv6_prefix>/64 dev lo
sysctl -w net.ipv6.ip_nonlocal_bind=1
```

Provider mode warning:
- If your /64 is L3-routed to the host, this works without per-/128 NDP.
- If your provider treats the /64 as on-link, you may need `ndppd` or explicit /128 assignment.

You must validate this with an external connectivity test before going live on port 25.

## 3) Install Dependencies

On Debian/Ubuntu:

```bash
apt-get update
apt-get install -y git ca-certificates curl
```

If you build from source, install Go (version must satisfy `go.mod`). This repo currently targets Go `1.24.x`.

## 4) Install (Recommended: Release Binaries)

This is the intended v1 operator experience: no Go toolchain required.

```bash
curl -fsSL https://raw.githubusercontent.com/<org-or-user>/sisumail/main/deploy/install.sh | sudo bash
```

Then edit `/etc/sisumail.env` and restart the relay.

## 5) Install (Alternative: Build From Source)

Public repo:

```bash
git clone https://github.com/<org-or-user>/sisumail.git
cd sisumail
go test ./...
go build -o /usr/local/bin/sisumail-relay ./cmd/sisumail-relay
```

## 6) Create Relay State Directories

```bash
mkdir -p /var/lib/sisumail /var/spool/sisumail
chmod 700 /var/lib/sisumail
```

## 7) Configure Secrets (Hetzner Console DNS Token)

Create `/etc/sisumail.env` with mode `0600`:

```bash
cat > /etc/sisumail.env <<EOF
HCLOUD_TOKEN=...                        # Hetzner Console/Cloud API token (Security -> API token)
SISUMAIL_DNS_ZONE=<zone>               # e.g. sisumail.fi
SISUMAIL_IPV6_PREFIX=<relay_ipv6>/64   # your routed /64
SISUMAIL_TIER2_LISTEN=127.0.0.1:2526   # staging default; set to :25 for production
SISUMAIL_TIER2_TLS_MODE=opportunistic  # disable|opportunistic|required (production: required)
SISUMAIL_TIER2_TLS_CERT=               # path to cert PEM for spool.<zone>
SISUMAIL_TIER2_TLS_KEY=                # path to key PEM for spool.<zone>
SISUMAIL_TIER2_DENYLIST_PATH=/etc/sisumail-tier2-denylist.txt
SISUMAIL_TIER2_MAX_CONNS_PER_SOURCE=20
SISUMAIL_TIER2_MAX_MSGS_PER_SOURCE_PER_MIN=60
SISUMAIL_OBS_LISTEN=127.0.0.1:9090     # relay health/readiness/metrics HTTP
SISUMAIL_TIER1_FAST_FAIL_MS=200        # quick offline failover to MX 20
SISUMAIL_TIER1_OPEN_TIMEOUT_MS=3000    # SSH smtp-delivery channel open timeout
SISUMAIL_TIER1_IDLE_TIMEOUT_MS=120000  # idle TCP/SSH pipe timeout
SISUMAIL_TIER1_MAX_CONN_DURATION_MS=600000
SISUMAIL_TIER1_MAX_BYTES_PER_CONN=10485760
SISUMAIL_TIER1_MAX_CONNS_PER_USER=10
SISUMAIL_TIER1_MAX_CONNS_PER_SOURCE=20
EOF
chmod 0600 /etc/sisumail.env
```

Quick validity check (must return `200`):

```bash
. /etc/sisumail.env
curl -sS -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer ${HCLOUD_TOKEN}" \
  "https://api.hetzner.cloud/v1/zones?name=${SISUMAIL_DNS_ZONE}"
```

## 8) Run via systemd (Dev Ports)

Start on dev ports to avoid lockout and avoid binding real port 25 prematurely:

- SSH gateway: `:2222` (product SSH, not admin OpenSSH)
- Tier 1 proxy: `:2525`

Example unit:

```ini
# /etc/systemd/system/sisumail-relay.service
[Unit]
Description=Sisumail Relay (dev ports)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/sisumail.env
ExecStart=/usr/local/bin/sisumail-relay \
  -ssh-listen :2222 \
  -tier1-listen :2525 \
  -db /var/lib/sisumail/relay.db \
  -hostkey /var/lib/sisumail/hostkey_ed25519
Restart=always
RestartSec=2

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sisumail /var/spool/sisumail

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
systemctl daemon-reload
systemctl enable --now sisumail-relay
systemctl status sisumail-relay --no-pager
```

## 9) Verify Claim + DNS Provisioning

Once nameservers have propagated and the token is valid:

- Connect as a new username with a new SSH key (first-come claim).
- The relay should allocate an IPv6 from your /64 and create DNS records for that user.

Inspect relay logs:

```bash
journalctl -u sisumail-relay -n 200 --no-pager
```

Observe service health locally:

```bash
curl -fsS http://127.0.0.1:9090/-/healthz
curl -fsS http://127.0.0.1:9090/-/readyz
curl -fsS http://127.0.0.1:9090/metrics | head
```

`/-/readyz` returns `503` until both SSH gateway and Tier 1 listeners are active.

Tier 2 denylist file format (`SISUMAIL_TIER2_DENYLIST_PATH`):

```text
# one entry per line (IP or CIDR)
203.0.113.10
198.51.100.0/24
2001:db8:bad::/48
```

## 10) Production Cutover (Later)

Do not do this until Tier 2 + hardening are ready.

- Bind Tier 1 on port `:25` on IPv6 AnyIP.
- Run Tier 2 spool MX on `spool.<zone>:25` with a publicly trusted TLS cert for that hostname.
- Move product SSH to `:22` only after you relocate admin OpenSSH to a different port and verify access.

For Tier 2 cutover with strict STARTTLS:

```bash
. /etc/sisumail.env
sed -i 's/^SISUMAIL_TIER2_LISTEN=.*/SISUMAIL_TIER2_LISTEN=:25/' /etc/sisumail.env
sed -i 's/^SISUMAIL_TIER2_TLS_MODE=.*/SISUMAIL_TIER2_TLS_MODE=required/' /etc/sisumail.env
# set cert/key paths:
# SISUMAIL_TIER2_TLS_CERT=/etc/letsencrypt/live/spool.<zone>/fullchain.pem
# SISUMAIL_TIER2_TLS_KEY=/etc/letsencrypt/live/spool.<zone>/privkey.pem
systemctl restart sisumail-tier2
systemctl status sisumail-tier2 --no-pager
```

## Operator Safety Notes

- Never commit DNS tokens, host keys, or ACME keys/certs to git.
- Treat Tier 2 as an email-processing component (plaintext exists transiently during ingest).
