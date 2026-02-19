# Sisumail Relay (Scratch Build)

Fast path build focused on VPS relay identity controls.

Current implemented core:

1. Invite-only account claim with fan-out policy `3 -> 2 -> 1 -> 0`.
2. First-come username claim (invite-gated).
3. Anti-spam/squat claim throttling (per-source + global limits).
4. Soft delete + restore account states.
5. Minimal HTTP relay API for claim/admin/user operations.
6. Ciphertext spool with 15-minute default TTL + manual delete + purge endpoint.
7. Per-account API keys (issued on claim, rotatable, revocable).
8. Landing page + invite-code claim flow.
9. Health, readiness, and metrics endpoints.
10. Runtime hardening: request/data size limits, HTTP timeout tuning, SMTP abuse controls.

## Run

```bash
go run ./cmd/sisumail-relay \
  -listen :8080 \
  -smtp-listen :2525 \
  -smtp-zone sisumail.fi \
  -spool-ttl 15m \
  -db ./sisumail-relay.db \
  -site-dir ./web \
  -invite-pepper "change-me" \
  -admin-token "change-me-admin" \
  -max-json-bytes 1048576 \
  -max-ciphertext-bytes 262144 \
  -smtp-max-data-bytes 262144 \
  -smtp-max-connections 200 \
  -smtp-per-ip-per-minute 120
```

## API (Current)

Public:

- `POST /v1/claim` -> claim username with invite (returns `api_key` once)
- `POST /v1/invite-requests` -> legacy invite-request endpoint (optional)

Landing pages:

- `GET /` -> sisumail.fi landing
- `GET /apply` -> invite-code claim form (invite + handle + pubkey)

SMTP ingress:

- Listens on `-smtp-listen` (default `:2525`)
- Accepts recipients:
  - `username@sisumail.fi`
  - `service@username.sisumail.fi`
- DATA payload must be ciphertext-like (`ciphertext:`, `age1`, or `ENC:` prefix)
- Enqueues to 15-minute spool by default (`-spool-ttl`)

Admin:

- `POST /v1/admin/mint-invites` -> mint root invites
- `GET /v1/admin/accounts/{username}` -> account status
- `POST /v1/admin/accounts/{username}/soft-delete`
- `POST /v1/admin/accounts/{username}/restore`
- `POST /v1/admin/messages` -> enqueue ciphertext message (default TTL 15m)
- `GET /v1/admin/messages?username=<u>` -> list unexpired messages
- `DELETE /v1/admin/messages/{username}/{id}` -> manual delete during TTL window
- `POST /v1/admin/purge-expired` -> remove expired messages now
- `GET /v1/admin/invite-requests?status=pending|acknowledged` -> list invite applications
- `POST /v1/admin/invite-requests/{id}/ack` -> mark invite application acknowledged

User (Bearer `api_key`):

- `GET /v1/me/account` -> own account status
- `GET /v1/me/messages` -> own unexpired messages
- `DELETE /v1/me/messages/{id}` -> own manual delete during TTL window
- `POST /v1/me/api-key/rotate` -> rotate own API key (old key revoked)

Worker:

- Auto purge expired spool messages with `-purge-interval` (default `30s`, `0` disables)
- Auto purge revoked API key metadata older than `-api-key-retention` (default `30d`)

Ops endpoints:

- `GET /healthz` -> liveness
- `GET /readyz` -> readiness (DB ping)
- `GET /metrics` -> Prometheus-style counters
