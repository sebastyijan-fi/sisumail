# Sisumail (New Vision)

See `WHITEPAPER.md` for the full architecture.

## Status (What Works vs What Doesn't Yet)

Working today (local harness + current relay):
- Tier 1 blind TCP proxy that pipes an inbound TCP connection into an SSH channel (`smtp-delivery`).
- Out-of-band sender metadata preface on the SSH channel (not injected into the SMTP stream).
- Client-side local SMTP daemon that requires STARTTLS before accepting MAIL/RCPT/DATA (confidentiality-first).
- Split-MX DNS record set implementation exists (`internal/provision` + `internal/dns/hetznercloud`).
- Identity registry (SQLite) with first-come claim semantics and per-user IPv6 allocation from a /64.

Not working yet / not complete (do not assume production-ready):
- Relay-mediated ACME control channel is not implemented yet (client-side DNS-01 automation is available).
- DANE/DNSSEC and MTA-STS hardening.
- Full production alerting/SLO dashboard integration is not complete yet (basic health/readiness/metrics endpoints are available).
- Production port plan (moving product SSH to `:22` safely while keeping admin OpenSSH access).

## Dev Quickstart (Local Harness)

This repo currently contains a minimal dev harness to prove:
- SSH session registry and `smtp-delivery` channels
- Tier 1 proxy piping a TCP connection into an SSH channel
- Client-side SMTP daemon with `RequireTLS=true` (STARTTLS required)
- Out-of-band sender metadata preface (not injected into SMTP stream)

### 1) Start the relay (dev ports)
```bash
go run ./cmd/sisumail-relay -ssh-listen :2222 -tier1-listen :2525 -dev-user niklas
```

### 2) Start the client
In another terminal:
```bash
go run ./cmd/sisumail -relay 127.0.0.1:2222 -user niklas -key ~/.ssh/id_ed25519 -smtp-listen 127.0.0.1:2526 -tls-policy pragmatic

# Enable ACME DNS-01 automation via relay control channel (default).
go run ./cmd/sisumail \
  -relay 127.0.0.1:2222 \
  -user niklas \
  -key ~/.ssh/id_ed25519 \
  -zone sisumail.fi \
  -tls-policy strict \
  -acme-dns01

# Optional: direct DNS mode (node holds HCLOUD token).
go run ./cmd/sisumail \
  -relay 127.0.0.1:2222 \
  -user niklas \
  -key ~/.ssh/id_ed25519 \
  -zone sisumail.fi \
  -tls-policy strict \
  -acme-dns01 \
  -acme-via-relay=false
```

Minimal command shell (chat-first, no heavy TUI):

```bash
go run ./cmd/sisumail \
  -relay sisumail.fi:22 \
  -user niklas \
  -key ~/.ssh/id_ed25519 \
  -zone sisumail.fi \
  -smtp-listen 127.0.0.1:2526 \
  -tls-policy pragmatic \
  -shell
```

Inside shell:
- `¤help`
- `¤whoami`
- `¤inbox`
- `¤read <id>`
- `¤history <user>`
- `¤<user> <message>` to send chat quickly

### 3) Simulate a sender delivering SMTP to Tier 1
In a third terminal:
```bash
nc 127.0.0.1 2525
```

You should see the SMTP banner from the client's local SMTP daemon, because the relay is piping bytes into the user's `smtp-delivery` channel.

## DNS (Split MX)

See `docs/dns-records.md` for the exact per-user record templates.

For relay health/readiness/metrics and initial alert guidance, see `docs/alerts-runbook.md`.
For real relay-mediated ACME verification on an operator host, use `scripts/smoke_acme_relay_live.sh`.
Latest live dogfooding findings are tracked in `docs/dogfood-notes-2026-02-11.md`.

## Next
Near-term build targets (in order):
- Production observability: health checks, metrics, alert thresholds, and runbooks.
- Tier 2 abuse tuning and automation (denylist maintenance process + adaptive policies).
- Relay-mediated ACME control channel (replace direct token-on-node flow).
- Node mode packaging and onboarding polish.
