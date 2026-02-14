# DNS Delegation (No Record Chaos)

Sisumail keeps your normal DNS provider as the authority for the parent zone (for example `sisumail.fi`), and delegates only a subzone for dynamic per-user IPv6.

## Why

Per-user `AAAA` records do not scale operationally. Delegation lets us answer `AAAA` dynamically from the identity registry DB.

## Model

For a user `<u>`:

- Public address: `inbox@<u>.sisumail.fi`
- Tier 1 MX target: `<u>.v6.sisumail.fi` (unique per user, IPv6 only)
- Tier 2 MX target: `spool.sisumail.fi` (shared, IPv4; optional fallback)

The parent zone keeps the small per-user set (`MX`, `TXT`, `CAA`). The `AAAA` record is served by `sisumail-dns`.

## Parent Zone Records (static)

You configure these once in your normal DNS provider:

- `NS v6.sisumail.fi -> ns1.sisumail.fi`
- `AAAA ns1.sisumail.fi -> <relay-public-ipv6>`

You can also add a second NS if you run a second DNS instance.

## Delegated Zone Records (dynamic)

`sisumail-dns` is authoritative for `v6.sisumail.fi` and answers:

- `AAAA <u>.v6.sisumail.fi -> <allocated IPv6 from relay.db>`

Unknown users return NXDOMAIN.

## Running `sisumail-dns`

Example:

```bash
sisumail-dns -zone v6.sisumail.fi. -db /var/lib/sisumail/relay.db -listen-udp :53 -listen-tcp :53
```

Notes:

- Run it on the same host as the identity registry DB, or give it read-only access to that DB.
- Keep the zone name as an FQDN with a trailing dot (`v6.sisumail.fi.`).

