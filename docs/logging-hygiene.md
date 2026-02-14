# Logging and Metadata Hygiene (v1)

This policy is mandatory for relay and node operations.

## Principle

- Keep routing metadata required for operation.
- Do not persist plaintext message bodies on relay storage.
- Treat alias/local-part data as sensitive user intelligence.

## Required Metadata Controls

The following fields must be documented and intentionally handled:

1. `HELO/EHLO`
2. `MAIL FROM`
3. `RCPT TO`
4. queue/message IDs
5. connection metadata (`source IP`, `port`, timing, byte counts)

## Current Sisumail v1 Behavior

- Tier 1:
  - Relay does blind TCP proxying and forwards sender metadata via out-of-band preface (`internal/proto/smtp_delivery_preface.go`).
  - After STARTTLS, relay cannot decrypt message headers/body.
- Tier 2:
  - Relay sees plaintext transiently during SMTP ingest, then encrypts immediately to user key.
  - Spool at rest is ciphertext-only (`internal/tier2/spool.go`, `internal/tier2/encrypt.go`).
- Client:
  - Alias extraction and alias policy stay local on user machine (`cmd/sisumail/main.go`, `internal/alias`).

## Operator Baseline

1. Keep observability endpoints local-only (`127.0.0.1`) unless protected.
2. Do not enable verbose SMTP debug logging in production.
3. Restrict retention of SMTP transaction logs to short operational windows.
4. Audit logs regularly to confirm alias/local-part data is not unnecessarily retained.
