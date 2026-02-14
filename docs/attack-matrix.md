# Sisumail Attack Matrix

This is the working red-team list for Sisumail receive infrastructure.

Goal: enumerate realistic attack vectors, then define concrete tests.

## Scope

- `sisumail` local client/runtime
- local `/app` and `/v1` APIs
- relay SSH channels and lookup paths
- Tier 1/Tier 2 mail ingress and storage
- chat (optional)
- profile/account switching and local data separation
- operator DNS/TLS/ACME controls

## Severity Legend

- `Critical`: identity takeover, remote code/data compromise, mass data loss
- `High`: unauthorized message/chat access or write, sustained outage
- `Medium`: strong confusion/abuse path, local-only compromise impact
- `Low`: quality or observability weakness that can hide bigger issues

## Attack Vectors and Tests

| ID | Vector | Severity | Expected Control | Test |
|---|---|---:|---|---|
| A01 | SSH private key theft from node | Critical | Key file `0600`, no plaintext copies, key rotation path | Verify perms and attempt auth with copied key from another host |
| A02 | Relay host-key MITM | Critical | strict `known_hosts` verify by default | Start client against fake relay host key; connection must fail |
| A03 | User runs with `-insecure-host-key` in production | High | explicit warning, documented non-prod only | Confirm warning logs and release docs reject this in prod examples |
| A04 | Profile confusion boots wrong identity | High | explicit profile control, clear UI identity display | Switch profiles repeatedly; verify inbox/chat data is profile-scoped |
| A05 | Profile selection causes auth lockout loop | High | safe default startup behavior | Set unsupported profile active and restart; client should still boot default |
| A06 | Local app CSRF-style mutation via browser | High | app session header (`X-Sisu-App-Token`) required | Trigger form/image POST from another local page; must return `401` |
| A07 | Loopback bypass for `/app/v1` | High | loopback-only enforcement | Send requests via non-loopback address; must return `403` |
| A08 | Bearer API token theft (`/v1`) | High | token in `0600` file, never rendered in app | grep logs/UI for token leakage; confirm absent |
| A09 | Stored XSS from message content | High | render with escaped text only | Send HTML/JS payload mail; ensure script does not execute |
| A10 | Header spoofing to force alias routing | High | trust controlled headers/metadata only | Inject `X-Sisumail-Alias` externally; verify alias logic is not spoofable |
| A11 | Alias bypass through malformed recipient | Medium | strict alias normalization | send recipient with unicode/control chars; must reject |
| A12 | Alias enumeration abuse | Medium | rate limit + no verbose leak | brute-force aliases and inspect response uniformity |
| A13 | Tier 1 SMTP abuse flood | High | size, recipient and connection limits | run burst SMTP sends and verify throttle/reject behavior |
| A14 | Tier 2 spool non-ciphertext write | High | ciphertext-only validation | attempt plaintext spool payload; must be rejected |
| A15 | Tier 2 replay attack (same ciphertext repeatedly) | Medium | dedupe/visibility alarms | replay same message ID repeatedly, verify handling and metrics |
| A16 | MIME/attachment decompression bomb | High | size caps + parse limits | send nested/big MIME payloads and watch memory/CPU behavior |
| A17 | Chat send to non-allowlisted peer | Medium | allowlist hard enforcement | `sisumail -chat-to bob` when bob not allowed; must block |
| A18 | Incoming chat from non-allowlisted peer | Medium | drop before storage | inject inbound chat from blocked peer; history remains unchanged |
| A19 | Chat channel unsupported on relay | Medium | clear degraded-mode UX and errors | validate app/CLI error message quality and operator runbook |
| A20 | Unauthorized message delete via app | High | app session token + profile scoping | attempt delete with missing token / wrong profile |
| A21 | Cross-profile data bleed (mail) | High | profile-specific storage roots | send/read in profile A; confirm profile B cannot see same IDs |
| A22 | Cross-profile data bleed (chat/contacts) | High | profile-specific chat/contact files | add contact and chat in A; verify absent in B |
| A23 | Local file permission drift | Medium | all security files `0600`, dirs `0700` | automated permission audit across config/state paths |
| A24 | Unsafe logs leak sensitive content | Medium | avoid tokens/key material in logs | inspect logs during full run including errors |
| A25 | ACME DNS control misuse | High | authenticated relay control channel only | attempt unauthorized ACME channel requests |
| A26 | DNS poisoning / wrong MX records | High | operator DNS checks and smoke tests | run DNS integrity script + manual dig validation |
| A27 | STARTTLS downgrade attempts | High | STARTTLS required locally | attempt plaintext SMTP delivery; must reject |
| A28 | Command/channel confusion on relay SSH | High | reject unknown channel types | fuzz channel open types and verify hard reject |
| A29 | Supply chain tampering of install script | High | checksum/signature verification | verify release artifacts/checksums before install |
| A30 | Dependency CVEs | Medium | regular dependency scan and patch cadence | run govulncheck/dependency scan on CI schedule |
| A31 | First-claim squatting / name flood | High | strict username rules + claim rate limits (per source + global) | attempt N new claims from one source bucket; must rate limit |

## Immediate Test Plan (Run Now)

1. Host key MITM guard (`A02`): fake relay key should fail.
2. App mutation CSRF check (`A06`, `A20`): POST delete/block without app token should fail.
3. Cross-profile separation (`A21`, `A22`): verify no bleed for mail/chat/contacts.
4. Tier 2 ciphertext-only (`A14`): ensure plaintext spool payload rejects.
5. Allowlist enforcement (`A17`, `A18`): blocked peers cannot send or persist.
6. STARTTLS enforcement (`A27`): local SMTP without STARTTLS must reject.

Automated randomized runner (current automated subset + manual coverage report):

```bash
scripts/security_vector_runner.sh --rounds 3 --parallel 4
```

## Gaps To Close Next

1. Extend live DNS automation coverage (`A26`) in CI by setting resolver/domain test env.
2. Ensure `govulncheck` is installed in CI runners so `A30` is fully automated.
3. Add structured security metrics: auth failures, blocked actions, replay attempts.

## Rule

Any `Critical` or `High` failure blocks release until fixed or explicitly risk-accepted with mitigation.

## Automation Coverage (Current)

Automated by `scripts/security_vector_runner.sh`:

- `A02`, `A03`, `A04`, `A05`, `A06`, `A08`, `A09`, `A10`, `A11`, `A12`, `A13`, `A14`, `A15`, `A16`, `A17`, `A19`, `A20`, `A21`, `A22`, `A23`, `A24`, `A25`, `A26`, `A27`, `A28`, `A29`
- `A30` is tool-conditional: automated when `govulncheck` is installed; otherwise reported as `MANUAL`.
- `A07` is environment-conditional: auto when non-loopback route path is available, otherwise reported as `MANUAL`.
