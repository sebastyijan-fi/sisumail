# Sisumail Threat Model (Baseline)

## Assets

- Account identities and status.
- Invite graph and invite redemption state.
- API key hashes and key lifecycle metadata.
- Spool ciphertext payloads and sender metadata.
- Admin operations and audit logs.

## Trust Boundaries

- Public HTTP API boundary.
- Public SMTP ingress boundary.
- Reverse proxy / TLS boundary.
- SQLite local storage boundary.
- Admin token handling boundary.

## Key Threats

- Unbounded payload DoS via HTTP or SMTP.
- Brute-force/abuse of claim and SMTP ingress paths.
- Token theft or weak admin secret handling.
- Information leakage via verbose server errors.
- Data loss due to missing backup/restore discipline.

## Current Mitigations

- Invite-gated claims with rate limits.
- Request body limits and SMTP DATA limits.
- HTTP timeout and header-size bounds.
- API key hashing and rotation/revocation flow.
- Sanitized internal error responses.
- Audit log lines for privileged actions.
- Health/readiness/metrics endpoints.

## Residual Risks

- Single-process SQLite architecture limits horizontal scale.
- Admin token model is still coarse-grained.
- No mTLS or IP allow-list enforcement on admin APIs by default.
- No formal per-endpoint authz scopes yet.

## Next Hardening Candidates

- Scoped admin credentials with least privilege.
- Dedicated SMTP reputation/abuse controls.
- Centralized structured log shipping and retention.
- Signed audit trail export.
