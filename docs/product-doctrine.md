# Sisumail Product Doctrine

This is the short version we can say to anyone, anywhere.

## One-Liner

Sisumail is sovereign mail receive infrastructure.

## What Sisumail Is

- A receive-first mailbox identity for verification links, resets, codes, and security-critical account mail.
- A local-first trust model where user keys and decryption stay on user-owned devices in the recommended mode.
- A relay + mailbox architecture that makes trust boundaries explicit and testable.
- Optional encrypted chat for coordination between Sisumail users.

## What Sisumail Is Not

- Not an outbound internet email sending platform.
- Not a social feed, ad network, or attention product.
- Not a replacement for every messaging workflow.

## Core Product Promises

- `Ownership`: user identity is bound to cryptographic keys, not to a centralized account password alone.
- `Legibility`: delivery tier and trust assumptions are visible, not hidden.
- `Portability`: users can move between hosted SSH, local session, and personal node.
- `No dark patterns`: no lock-in UX, no surveillance incentives, no growth hacks that weaken user control.

## Modes (Simple Language)

- `Hosted SSH`: easiest first login and recovery, with higher relay trust.
- `Local Session` (recommended): everyday mode with strongest practical trust boundary for most users.
- `Personal Node`: most control, most responsibility.

## Public vs Private Deployments

Any operator (for example `bank.com`) can run Sisumail in different policy shapes:

- `Public`: receives from the open internet with strong abuse controls.
- `Private`: restricted sender policy for internal or partner-only workflows.
- `Hybrid`: public ingress with stricter controls for sensitive aliases.

## Naming Direction

For user clarity, prefer:

- `gateway` for internet-facing ingress/routing role.
- `mailbox` for user-owned key/decrypt/store role.

Internal code can migrate gradually, but external language should be consistent now.

## Non-Negotiables

- Receive-first mail stays the core.
- Security beats growth shortcuts.
- Local mode quality must surpass hosted-shell convenience over time.
- Optional chat remains secondary and must never confuse the product boundary.

## Tier 2 (Compatibility Bridge)

- Tier 1 is the product: the relay becomes content-blind after STARTTLS.
- Tier 2 exists only for legacy SMTP compatibility and optional offline delivery.
- Tier 2 is **opt-in per user**. If a user has not enabled Tier 2, Tier 2 MUST reject delivery attempts for that user.
