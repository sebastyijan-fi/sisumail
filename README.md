# Sisumail (New Vision)

See `WHITEPAPER.md` for the full architecture.

## Product Framing (Plain English)

Sisumail is sovereign mail **receive** infrastructure.

- You receive mail at an identity/domain you control.
- Your private keys and decryption stay on your own device in local mode.
- Sisumail is **not** an outbound email sending platform.
- Optional encrypted chat exists for coordination, not to replace email.

## Status (What Works vs What Doesn't Yet)

Working today (local harness + current relay):
- Tier 1 blind TCP proxy that pipes an inbound TCP connection into an SSH channel (`smtp-delivery`).
- Out-of-band sender metadata preface on the SSH channel (not injected into the SMTP stream).
- Client-side local SMTP daemon that requires STARTTLS before accepting MAIL/RCPT/DATA (confidentiality-first).
- Split-MX DNS record set implementation exists (`internal/provision` + `internal/dns/hetznercloud`).
- Identity registry (SQLite) with first-come claim semantics and per-user IPv6 allocation from a /64.

Not working yet / not complete (do not assume production-ready):
- DANE/DNSSEC and MTA-STS hardening.
- Full production alerting/SLO dashboard integration is not complete yet (basic health/readiness/metrics endpoints are available).
- Hosted SSH shell is now interactive (`help`, `whoami`, `status`, `lookup`, `chatq`, quick encrypted chat), but full encrypted mailbox-reading UX in SSH-only mode is still in progress.

## Access Modes (Crystal Clear)

Sisumail supports three user-facing modes. They are intentionally different in trust assumptions.

1. Hosted SSH Session (easiest)
- Login: `ssh -p 2222 <username>@sisumail.fi`
- Goal: instant access, no local install.
- Trust: higher relay trust (session/UI runs on relay side).

2. Local Session (sovereign default)
- Run local client binary (`sisumail`) against `sisumail.fi`.
- Goal: keep keys/decryption/storage on user device.
- Trust: stronger privacy boundary (relay routes, local endpoint handles content).

3. Personal Node (power users)
- Always-on user-managed node/domain.
- Goal: persistence and control.
- Trust: strongest user control, highest operational burden.

Current implementation status:
- Hosted SSH mode: interactive command shell available with account bootstrap + encrypted chat + queue/status.
- Local session mode: most complete feature set today (mail/chat + storage + ACME relay flow).
- Personal node mode: available but onboarding/packaging still improving.

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

### Install Client (User-Friendly)

Install `sisumail` to `~/.local/bin` (no root/systemd):

```bash
curl -fsSL https://raw.githubusercontent.com/sebastyijan-fi/sisumail/main/scripts/install_client.sh | bash
```

Then run:

```bash
sisumail -init
sisumail
```

### 2) Start the client
In another terminal:
```bash
go run ./cmd/sisumail -relay 127.0.0.1:2222 -user niklas -key ~/.ssh/id_ed25519 -insecure-host-key -smtp-listen 127.0.0.1:2526 -tls-policy pragmatic

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

### Local App API (Preview)

By default, `sisumail` starts the local app/API on `127.0.0.1:3490`.

Run:

```bash
sisumail
```

Open browser UI:

```text
http://127.0.0.1:3490/app
```

No token paste is needed in `/app` (it is local-only).

Advanced override (custom bind/disable):

```bash
sisumail -api-listen 127.0.0.1:4590
sisumail -api-listen ""
```

Read token only for direct API clients:

```bash
cat ~/.config/sisumail/api-token
```

Query endpoints:

```bash
TOKEN="$(cat ~/.config/sisumail/api-token)"
curl -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:3490/v1/status
curl -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:3490/v1/inbox
curl -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:3490/v1/message/<id>
```

Note: relay host key verification is enabled by default. For local ephemeral dev relays, pass `-insecure-host-key`.

Zero-flag local flow (after one-time init):

```bash
sisumail -init \
  -relay sisumail.fi:2222 \
  -user <username> \
  -key ~/.ssh/id_ed25519 \
  -zone sisumail.fi \
  -shell

# daily use
sisumail
```

Config path default: `~/.config/sisumail/config.env` (override with `-config`).

Minimal command shell (mail receive + optional chat, no heavy TUI):

```bash
go run ./cmd/sisumail \
  -relay sisumail.fi:2222 \
  -user niklas \
  -key ~/.ssh/id_ed25519 \
  -zone sisumail.fi \
  -smtp-listen 127.0.0.1:2526 \
  -tls-policy pragmatic \
  -shell
```

Product SSH-only hosted session (zero local install):

```bash
ssh -p 2222 <username>@sisumail.fi
```

Note: this is intentionally a different trust mode than local `sisumail` client usage.

Inside shell:
- `help`
- `examples`
- `whoami`
- `status`
- `lookup <user>`
- `chatq`
- `mailq`
- `<user> <message>` to send a quick encrypted chat note
  - Optional command prefixes are still accepted: `/` and `¤`.
  - Output shows delivery mode explicitly: `delivered-live` or `queued-encrypted`.

Reminder: Sisumail does not send outbound internet email for your domain; it is receive-first.

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
For local hosted-shell command-loop checks, use `scripts/smoke_hosted_shell_local.sh`.
For hosted SSH UX verification on a real claimed user, use `scripts/smoke_hosted_shell_live.sh`.
Latest live dogfooding findings are tracked in `docs/dogfood-notes-2026-02-11.md`.
Access-mode trust differences are documented in `docs/access-modes.md`.
Core product stance is documented in `docs/product-doctrine.md`.
Release quality/security bar is documented in `docs/security-release-gate.md`.
Conformance artifacts and checks are documented in `docs/conformance.md`.
Logging/metadata hygiene policy is documented in `docs/logging-hygiene.md`.
Execution roadmap is documented in `docs/roadmap-sovereign-mail.md`.
Automated release gate command: `scripts/release_gate.sh` (add `--with-smoke` for full local validation).
Local release artifact builder: `scripts/package_release_local.sh`.
Email-only app-path dogfood script: `scripts/dogfood_email_app_local.sh`.

## Next
Near-term build targets (in order):
- Production observability: health checks, metrics, alert thresholds, and runbooks.
- Tier 2 abuse tuning and automation (denylist maintenance process + adaptive policies).
- Relay-mediated ACME control channel (replace direct token-on-node flow).
- Node mode packaging and onboarding polish.
