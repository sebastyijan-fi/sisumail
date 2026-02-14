# Security Release Gate

No production release should ship unless every `P0` gate below is green.

## P0: Must Pass

1. `Receive-only boundary`
- Domain templates enforce `SPF -all` for Sisumail identities.
- Product copy does not imply outbound email support.

2. `Tier integrity`
- Tier 1 and Tier 2 delivery paths are both test-covered.
- Message metadata clearly records the delivery tier.

3. `Key ownership`
- User identity remains bound to SSH key material.
- No fallback auth path silently bypasses key checks.

4. `Encryption hygiene`
- Tier 2 spool stores ciphertext only.
- Hosted relay surfaces that encrypted content cannot be decrypted there.

5. `Abuse controls`
- Tier 1 and Tier 2 source limits are enforced.
- Chat and key-lookup rate limits are enforced.

6. `Operational visibility`
- Health/readiness endpoints are available.
- Metrics expose queue pressure, failures, and limit events.

7. `Safe defaults`
- Insecure or dev-only flags are explicit and documented as non-production.
- Production examples use strict TLS paths where applicable.

8. `Conformance evidence`
- `conformance/declaration.json` exists and is current.
- Profile reports are generated from code/docs and all `MUST` checks pass.

## P1: Strongly Recommended Before Scale

1. DANE/DNSSEC posture documented and staged.
2. MTA-STS and downgrade-risk mitigations tightened.
3. Standardized operator drills for failover and recovery.
4. Soak test report for reconnect, spool drain, and restart scenarios.

## Verification Commands (Current Repo)

Run before release:

```bash
scripts/release_gate.sh
```

Run conformance checks directly:

```bash
scripts/conformance_check.sh --strict
```

Run full local validation (includes smoke scripts):

```bash
scripts/release_gate.sh --with-smoke
```

Run dependency vulnerability scan (requires `govulncheck`):

```bash
scripts/release_gate.sh --with-vuln
```

Run app-path dogfood (email-only + local API):

```bash
scripts/dogfood_email_app_local.sh
```

For live operator validation:

```bash
scripts/release_gate.sh --with-live
```

Optional DNS integrity check helper:

```bash
scripts/dns_integrity_check.sh --template-only
# live mode (requires dig + reachable resolver):
scripts/dns_integrity_check.sh --live-required --domain sisumail.fi --user niklas
```

Live VPS hardening audit (SSH required):

```bash
scripts/vps_attack_surface_audit.sh --host 77.42.70.19
# strict mode fails on warnings too:
scripts/vps_attack_surface_audit.sh --host 77.42.70.19 --strict
```

Attack-surface checklist and red-team vectors:

```bash
docs/attack-matrix.md
```

## Release Rule

If any `P0` gate fails, we do not ship.
