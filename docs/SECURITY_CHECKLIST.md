# Sisumail Security Checklist

## Pre-Deploy

- Set strong `-invite-pepper`.
- Set strong `-admin-token` (or multiple comma-separated tokens).
- Ensure TLS termination is active.
- Confirm DNS A/AAAA/MX are correct.
- Confirm HTTP and SMTP ports are restricted by firewall policy.

## Runtime Controls

- Verify `-max-json-bytes` is set.
- Verify `-max-ciphertext-bytes` is set.
- Verify `-smtp-max-data-bytes` is set.
- Verify `-smtp-max-connections` is set.
- Verify `-smtp-per-ip-per-minute` is set.

## Authentication & Authorization

- Verify admin endpoints require bearer token.
- Rotate admin token on a schedule.
- Audit logs for admin actions are retained.
- User API keys are rotatable and old keys are revoked.

## Monitoring

- Track 401 and 5xx rates.
- Track SMTP rejection spikes.
- Track readiness failures.
- Alert on sudden claim-failure increases.

## Data Safety

- Backup SQLite database regularly.
- Test restores periodically.
- Verify revoked API key purge retention is configured.
- Verify spool TTL and purge worker are enabled.
