# Relay Operator Quickstart (VPS)

This is a **relay operator** guide: you run the infrastructure for a domain (DNS + IPv6 AnyIP + Tier 1 proxy + SSH gateway, and later Tier 2 spool).

If you only want to run a personal always-on node that connects to an existing relay, you do **not** need this doc (node mode docs not written yet).

## Core Product Message (Use This Wording)

When users ask what Sisumail is, keep it simple:

- Sisumail is sovereign **mail receive** infrastructure.
- It is **not** an outbound email sending platform.
- Optional encrypted chat exists for coordination.

## Current Reality (Read First)

Working today:
- Tier 1 proxy + SSH gateway (dev ports by default).
- Identity registry (SQLite) and first-come claim semantics.
- Hetzner Console DNS (Cloud API) provisioning exists and is wired into the relay **if** env vars are present.
- Product SSH gateway on `:2222` with admin OpenSSH on `:22` can be run safely.

Not production-ready yet:
- Full observability stack (metrics endpoint, alerting policy, SLO dashboards) is not complete.
- Hosted SSH shell is live and interactive, but encrypted mailbox-reading UX in hosted-only mode is still under active iteration.

## User Access Modes (Operator View)

Operators should communicate mode/trust expectations clearly:

1. Hosted SSH session (`ssh <user>@sisumail.fi`)
- Easiest access path.
- Relay-hosted interface logic; higher relay trust.
- No local repo clone is required for this mode.
- Good for first login and recovery.

2. Local session (`sisumail` client on user machine)
- Stronger privacy boundary; local endpoint handles keys/decryption/storage.
- Recommended day-to-day mode.

3. Personal node
- User-managed always-on endpoint for maximum control.

## Prereqs

- A VPS with:
  - 1 static IPv4
  - a routed IPv6 /64 (preferred) or a provider-supported equivalent
- A domain you control (example: `sisumail.fi`)
- DNS zone managed in **Hetzner Console DNS** (Zones API via Hetzner Cloud API token).

## 1) Provision DNS (Split MX Model)

Per user `<u>` you will publish:

- `MX 10 <u>.v6.<zone>` (Tier 1)
- `MX 20 spool.<zone>` (Tier 2 fallback)
- `AAAA <u>.v6.<zone> -> <unique per-user IPv6>` (served by `sisumail-dns`)

Templates: see `docs/dns-records.md`.

## 1b) Publish `/.well-known/sisu-node`

v1 discovery should expose authoritative node metadata at:

```text
https://<your-domain>/.well-known/sisu-node
```

Generate the JSON artifact:

```bash
scripts/generate_well_known_sisu_node.sh \
  --domain sisumail.fi \
  --node-public-key <base64-ed25519-node-pubkey> \
  --ssh-endpoint sisumail.fi:2222 \
  --tier2-smtp spool.sisumail.fi:25 \
  --out /var/www/sisumail/.well-known/sisu-node
```

Template reference: `deploy/well-known/sisu-node.example.json`.

## 2) Enable IPv6 AnyIP (Tier 1 ingress)

Tier 1 requires the relay to accept inbound SMTP on **many** destination IPv6 addresses from your /64.

Recommended Linux primitive (AnyIP):

```bash
ip -6 route add local <relay_ipv6_prefix>/64 dev lo
sysctl -w net.ipv6.ip_nonlocal_bind=1
```

Provider mode warning:
- If your /64 is L3-routed to the host, this works without per-/128 NDP.
- If your provider treats the /64 as on-link (Hetzner-style), you need `ndppd` or explicit /128 assignment.

You must validate this with an external connectivity test before going live on port 25.

One-command helper for on-link /64s (installs `ndppd`, sysctls, AnyIP route, and sets Tier 1 listen to IPv6 `:25`):

```bash
scripts/vps_enable_tier1_anyip.sh --host <your-vps-ip>
```

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

Create `/etc/sisumail.env` with restricted perms (recommended: `0640 root:sisu`):

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
SISUMAIL_WELL_KNOWN_LISTEN=:8080        # optional public discovery HTTP listener
SISUMAIL_WELL_KNOWN_PATH=/.well-known/sisu-node
SISUMAIL_WELL_KNOWN_FILE=/etc/sisumail/sisu-node.json
SISUMAIL_TIER1_FAST_FAIL_MS=200        # quick offline failover to MX 20
SISUMAIL_TIER1_OPEN_TIMEOUT_MS=3000    # SSH smtp-delivery channel open timeout
SISUMAIL_TIER1_IDLE_TIMEOUT_MS=120000  # idle TCP/SSH pipe timeout
SISUMAIL_TIER1_MAX_CONN_DURATION_MS=600000
SISUMAIL_TIER1_MAX_BYTES_PER_CONN=10485760
SISUMAIL_TIER1_MAX_CONNS_PER_USER=10
SISUMAIL_TIER1_MAX_CONNS_PER_SOURCE=20
SISUMAIL_ACME_DNS01_PER_USER_PER_MIN=30
EOF
chown root:sisu /etc/sisumail.env
chmod 0640 /etc/sisumail.env
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
- For open first-claim, keep claim rate limits enabled (defaults are conservative). Tuning knobs:
- `SISUMAIL_CLAIM_PER_SOURCE_PER_HOUR` (default `3`)
- `SISUMAIL_CLAIM_PER_SOURCE_PER_DAY` (default `12`)
- `SISUMAIL_CLAIM_GLOBAL_PER_HOUR` (default `200`)
- `SISUMAIL_CLAIM_GLOBAL_PER_DAY` (default `1000`)
- `SISUMAIL_CLAIM_LOG_RETENTION_DAYS` (default `30`)

Inspect relay logs:

```bash
journalctl -u sisumail-relay -n 200 --no-pager
```

Observe service health locally:

```bash
curl -fsS http://127.0.0.1:9090/-/healthz
curl -fsS http://127.0.0.1:9090/-/readyz
curl -fsS http://127.0.0.1:9090/metrics | head
curl -fsS http://127.0.0.1:8080/.well-known/sisu-node
```

`/-/readyz` returns `503` until both SSH gateway and Tier 1 listeners are active.

Tier 2 denylist file format (`SISUMAIL_TIER2_DENYLIST_PATH`):

```text
# one entry per line (IP or CIDR)
203.0.113.10
198.51.100.0/24
2001:db8:bad::/48
```

Relay ACME control channel:
- When `HCLOUD_TOKEN`, `SISUMAIL_DNS_ZONE`, and `SISUMAIL_IPV6_PREFIX` are configured, the relay also enables authenticated `acme-dns01` control for connected users.
- Nodes can run `sisumail -acme-dns01` without local DNS API tokens (default behavior uses relay channel).

Live ACME relay smoke test (staging CA by default):

```bash
scripts/smoke_acme_relay_live.sh
```

Live hosted SSH shell smoke test (requires claimed user key):

```bash
SSH_USER=<claimed_user> scripts/smoke_hosted_shell_live.sh
```

Optional overrides:
- `ACME_DIR` (default Let’s Encrypt staging)
- `RELAY_ADDR`, `SMTP_LISTEN`, `ZONE`, `PROP_WAIT`, `TIMEOUT_SECS`

## Go Relay Canary (Parallel Validation)

To run the Go relay in parallel (new ports, isolated state) on a VPS without touching active Python services:

```bash
scripts/vps_deploy_go_canary.sh --host 77.42.70.19 --user root
```

Default canary ports:
- SSH: `3222`
- Tier 1: `2625`
- Well-known: `18080`
- Observability: `127.0.0.1:19090`

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
