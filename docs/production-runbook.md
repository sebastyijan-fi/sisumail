# Production Runbook (Relay-Node)

This is the canonical, linear path to running a Sisumail relay-node for a domain.

Sisumail is receive-only infrastructure. It does not send outbound internet email for your users.

## 0) Inputs You Need

- Domain: `<zone>` (example: `sisumail.fi`)
- VPS:
  - static IPv4
  - routed IPv6 `/64`
- DNS provider access for `<zone>` (for delegation + MX/TXT/CAA records)
- Hetzner Console/Cloud API token if you want automatic DNS provisioning (`HCLOUD_TOKEN`)

## 1) Install

On the VPS:

```bash
curl -fsSL https://sisumail.fi/install.sh | bash
```

This installs:
- `sisumail-relay` (SSH gateway + Tier1 proxy)
- `sisumail-tier2` (optional compatibility spool)
- `sisumail-dns` (authoritative DNS for delegated `v6.<zone>`)

## 2) Configure `/etc/sisumail.env`

Minimum:

- `SISUMAIL_DNS_ZONE=<zone>`
- `SISUMAIL_IPV6_PREFIX=<your /64>`
- `SISUMAIL_INVITE_PEPPER=<random secret>`

Recommended production policy:

- `SISUMAIL_ALLOW_CLAIM=false` (invite-only)
- Tier1:
  - `SISUMAIL_TIER1_LISTEN=[::]:25`
- Tier2:
  - keep disabled unless you explicitly want legacy compatibility

Restart:

```bash
systemctl restart sisumail-relay
systemctl restart sisumail-dns
```

## 3) Enable IPv6 AnyIP (Tier 1 ingress)

Sisumail Tier1 needs AnyIP so the relay can accept inbound SMTP on many destination IPv6 addresses from your `/64`.

Use the helper:

```bash
scripts/vps_enable_tier1_anyip.sh --host <vps-ip>
```

## 4) Delegate the `v6.<zone>` DNS Subzone

In your DNS provider for `<zone>`:

1. Create NS delegation:
   - `v6.<zone> NS ns1.<zone>`
2. Point `ns1.<zone>` to your relay's public IPv6:
   - `ns1.<zone> AAAA <relay-ipv6>`

After this, `sisumail-dns` serves dynamic per-user:
- `AAAA <user>.v6.<zone> -> <allocated IPv6>`

## 5) Publish Tier 2 Host (Optional)

If you enable Tier2 fallback:

- `spool.<zone> A <relay-ipv4>`

## 6) Publish Discovery (`/.well-known/sisu-node`)

Generate the discovery JSON and serve it from:

```text
https://<zone>/.well-known/sisu-node
```

Template: `deploy/well-known/sisu-node.example.json`.

## 7) Sanity Check (Doctor)

On the VPS:

```bash
sisumail-relay -doctor
```

On a client device:

```bash
sisumail -doctor
```

## 8) Mint Invites and Onboard

Mint invite codes (printable):

```bash
sisumail-relay -mint-invites -mint-invites-n 20
```

Users claim via the client/app using `claim-v1` (no open first-claim).

