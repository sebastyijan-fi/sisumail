# Sisumail Operations Runbook

## Deployment Baseline

- Run API behind Caddy with HTTPS enabled.
- Expose SMTP only if needed and keep relay limits enabled.
- Keep `-invite-pepper` and `-admin-token` in secret management, not in shell history.

## Health Checks

- Liveness: `GET /healthz` should return `200`.
- Readiness: `GET /readyz` should return `200`; `503` means DB unavailable.
- Metrics: `GET /metrics` exports counters for HTTP, claims, SMTP and purge.

## Backups

- SQLite database file is the source of truth (`-db` path).
- Use periodic hot-copy backup at least every 15 minutes:

```bash
sqlite3 /path/to/sisumail-relay.db ".backup '/backups/sisumail-relay-$(date +%F-%H%M%S).db'"
```

- Keep at least:
  - 7 days hourly snapshots
  - 30 days daily snapshots

## Restore Drill

1. Stop relay process.
2. Restore chosen backup file to the configured `-db` path.
3. Start relay process.
4. Validate:
   - `GET /readyz` returns `200`
   - claim/auth paths work for a known test account.

## Alerts (Minimum)

- `readyz` non-200 for >1 minute.
- `sisumail_http_errors_total` rate spike.
- `sisumail_smtp_rejected_total` sustained spike.
- TLS cert expiry alert from Caddy.

## Incident Triage

1. Check process/service status.
2. Check `/readyz`.
3. Check recent logs for `request_id=` and `audit action=`.
4. Check `/metrics` trend for error/reject counters.
5. If data integrity concern exists, stop writes and restore from latest valid backup.
