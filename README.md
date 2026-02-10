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
- Tier 2 as a real public MX on `spool.<zone>:25` with a publicly trusted TLS certificate (we currently run it in staging on `127.0.0.1:2526` via `sisumail-tier2`).
- Tier 2 delivery signaling integrated end-to-end (today it can spool ciphertext, but there is no real-time notify-to-client path yet).
- ACME DNS-01 certificate issuance for Tier 1 device certificates (control channel not implemented).
- TUI (Bubbletea) and mailbox UX (listing/reading mail) beyond the basic harness logging.
- Relay hardening requirements from the whitepaper (rate limits, bandwidth caps, backpressure, strict timeouts) are not fully implemented.
- Production port plan (moving product SSH to `:22` safely while keeping admin OpenSSH access).
- DANE/DNSSEC and MTA-STS hardening.

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
- Make Tier 2 a real spool MX service (TLS cert for `spool.<zone>`, listen on `:25`, stream-encrypt-on-ingest, ciphertext-only store).
- Production-grade relay controls for Tier 1 (caps/timeouts/backpressure as MUSTs from `WHITEPAPER.md`).
- DNS provisioning on claim using Hetzner Console DNS (Cloud API) token (`HCLOUD_TOKEN`).
- Safer operator workflow: release binaries + `deploy/install.sh` + `sisumail-update` timer.
- Client UX: Maildir storage + minimal TUI.
