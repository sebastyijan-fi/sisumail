# DNS Record Templates

Exact DNS records provisioned per user, derived from `WHITEPAPER.md` (§7 Split MX Architecture).

## Per-User Record Set

For user `<u>` with allocated IPv6 `<ipv6>`:

| # | Type | Name | Value | TTL | Purpose |
|---|------|------|-------|-----|---------|
| 1 | MX | `<u>.sisumail.fi` | `10 v6.<u>.sisumail.fi.` | 300 | Tier 1 primary (blind relay) |
| 2 | MX | `<u>.sisumail.fi` | `20 spool.sisumail.fi.` | 300 | Tier 2 fallback (encrypted spool) |
| 3 | AAAA | `v6.<u>.sisumail.fi` | `<ipv6>` | 300 | Tier 1 destination (unique per user) |
| 4 | TXT | `<u>.sisumail.fi` | `v=spf1 -all` | 3600 | SPF: receive-only, reject all sends |
| 5 | CAA | `<u>.sisumail.fi` | `0 issue "letsencrypt.org"` | 3600 | Restrict CA to Let's Encrypt (ACME) |

## Rationale

- **Split MX** (records 1–2): Senders that can reach the AAAA use Tier 1 (content-blind after STARTTLS). IPv4-only senders or senders that can't connect fall back to Tier 2 (encrypt-on-ingest).
- **Separate hostnames**: `v6.<u>.sisumail.fi` and `spool.sisumail.fi` have different TLS certificate holders — the user device and the relay, respectively.
- **SPF `-all`**: Sisumail is receive-only. No outbound mail from `<u>.sisumail.fi` is legitimate.
- **CAA**: Restricts certificate issuance to Let's Encrypt, matching the ACME DNS-01 flow.

## Shared Infrastructure Records (provisioned once)

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| A | `spool.sisumail.fi` | `<relay-ipv4>` | Tier 2 MX target |
| AAAA | `spool.sisumail.fi` | `<relay-ipv6-shared>` | Tier 2 MX target (recommended: dual-stack) |

## Implementation

- **Create**: `internal/provision/provision.go` → `ProvisionUser(username, destIPv6)`
- **Delete**: `internal/provision/provision.go` → `DeprovisionUser(username)`
- **Backend**: `internal/dns/hetzner/client.go` → Hetzner DNS API
