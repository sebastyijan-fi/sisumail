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
- ACME DNS-01 certificate issuance for Tier 1 device certificates (control channel not implemented).
- DANE/DNSSEC and MTA-STS hardening.
- Production observability package (metrics endpoint, alerts, SLO dashboards) is not complete yet.
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
```

### 3) Simulate a sender delivering SMTP to Tier 1
In a third terminal:
```bash
nc 127.0.0.1 2525
```

You should see the SMTP banner from the client's local SMTP daemon, because the relay is piping bytes into the user's `smtp-delivery` channel.

## DNS (Split MX)

See `docs/dns-records.md` for the exact per-user record templates.

## Next
Near-term build targets (in order):
- Production observability: health checks, metrics, alert thresholds, and runbooks.
- Abuse controls beyond channel limits (SMTP ingress policies for Tier 2 and operator ban workflows).
- ACME DNS-01 issuance flow for Tier 1 node certificates.
- Node mode packaging and onboarding polish.
