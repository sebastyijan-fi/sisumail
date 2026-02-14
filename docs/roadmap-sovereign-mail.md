# Roadmap: Sovereign Receive-Only Mail

This roadmap favors trust, reliability, and user ownership over feature sprawl.

## Track 1: Receive Path Reliability (Now)

Goal: inbound mail lands correctly under real-world sender behavior.

Milestones:

1. Harden split-MX behavior under offline/online transitions.
2. Expand replayable smoke tests for Tier 1 fast-fail and Tier 2 fallback.
3. Standardize operator runbook for DNS, AnyIP, and queue debugging.

Acceptance:

- Live test mail from mainstream senders reaches correct mailbox identity.
- Offline user reconnect reliably drains encrypted spool.
- Failure modes are visible via logs and metrics with actionable messages.

## Track 2: Security Hardening (Next)

Goal: improve downgrade resistance and tighten trust posture.

Milestones:

1. Stage DANE/DNSSEC rollout plan.
2. Add MTA-STS posture guidance and validation checks.
3. Enforce stricter production config checks in operator docs and scripts.

Acceptance:

- Clear operator checklist for TLS and DNS hardening.
- Regression tests cover known downgrade and misconfiguration classes.

## Track 3: Local-First UX (Core Product)

Goal: daily use is simply `sisumail`, not SSHing into a VPS.

Milestones:

1. Strengthen `sisumail -init` as the default onboarding path.
2. Improve local shell/inbox ergonomics and first-run status clarity.
3. Keep hosted SSH explicitly labeled as bootstrap/recovery mode.

Acceptance:

- New user can complete setup and receive mail with minimal flags.
- Product copy consistently recommends local mode for day-to-day use.

## Track 4: Builder Surface (Without Breaking Sovereignty)

Goal: allow app developers to build UX on top of user-owned mailbox runtime.

Milestones:

1. Define a local API contract (`localhost`) for inbox list/read/status events.
2. Add scoped local auth tokens for third-party UI clients.
3. Document an Android-friendly integration path.

Acceptance:

- Third-party UI can render inbox and status without extracting private keys.
- User can revoke local app tokens safely.

## Track 5: Multi-Operator Internet

Goal: many independent operators can run Sisumail for their own domains.

Milestones:

1. Clarify role names and packaging (`gateway`, `mailbox`).
2. Publish operator conformance checks and reference deployment profiles.
3. Add migration guidance across hosted, local, and personal node modes.

Acceptance:

- Different operators can deploy consistently without private tribal knowledge.
- Users can move modes without identity breakage.

## Guardrail

Every track must preserve this boundary:

- Sisumail is sovereign receive-only mail infrastructure.
- Optional encrypted chat remains secondary coordination.
- Sisumail does not become an outbound bulk-sending platform.
