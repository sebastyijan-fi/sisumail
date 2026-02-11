# Sisumail Whitepaper
**Title:** Sisumail: Blind-Relay Email Identities Bound to SSH Keys  
**Version:** 1.0  
**Date:** February 2026  
**Status:** Whitepaper (Architecture + Threat Model + Roadmap)

## Abstract
Sisumail is a receive-only email identity system where a user's SSH key is the sole credential: it authenticates access, binds identity, and derives encryption keys. Sisumail's primary delivery path (Tier 1) is a blind Layer-4 relay that routes inbound SMTP by destination IPv6 address and never terminates TLS; after STARTTLS, the relay cannot decrypt message headers or bodies because the TLS session terminates on the user's device. For compatibility with IPv4-only senders and optional offline delivery, Sisumail provides Tier 2 "encrypted spool" fallback: the relay terminates SMTP/TLS, sees plaintext transiently during ingest, encrypts the full RFC 5322 message immediately to the user's key, and stores or streams ciphertext only. Every message is labeled with the tier used, so the security properties are testable and user-visible.

Sisumail is not trying to replace conversational email workflows. It is a sovereign receive-only identity mailbox for the internet's account-creation and account-recovery ceremony: verification links, password resets, 2FA fallback codes, and service notifications.

Sisumail also provides end-to-end encrypted (E2E) user-to-user chat using the same identity keys. The relay routes encrypted blobs but cannot read chat content.

Reader orientation:
- Sisumail is **not** "email without reply"; it is a cryptographically owned receive-only identity anchor for internet account workflows.
- SSH is the protocol/auth/authz layer, **not** a permanent UX limitation. Terminal UX is first, but third-party clients can implement richer interfaces on top.

## 1. Motivation
Most users do not primarily need a full outbound/inbound email suite for rich conversation. They need a mailbox they cryptographically own for registrations, verifications, recovery flows, and notifications across internet services.

Operating a trustworthy mailbox identity is still hard because traditional self-hosting requires:

- stable IP reputation and deliverability infrastructure
- always-on availability
- correct TLS, DKIM/DMARC, DNS, abuse handling
- storage and client UX

At the same time, centralized email providers necessarily terminate TLS and process plaintext mail, making them powerful metadata and content intermediaries. Sisumail decouples these concerns:

- the relay provides minimal delivery infrastructure
- Tier 1 makes "relay cannot read content after STARTTLS" true by design
- Tier 2 provides pragmatic compatibility and offline storage with explicitly weaker trust assumptions
- users can start with "presence mode" and later upgrade to "node mode" without changing identity

## 2. Goals and Non-Goals

### 2.1 Goals
- **Minimize server trust by default:** Tier 1 is content-blind after STARTTLS.
- **SSH key = identity:** no passwords, no registration forms; first claim binds a key.
- **Edge ownership:** alias intelligence and message storage live on user hardware (node mode) or are ephemeral (terminal mode).
- **Honest, testable claims:** every message states how it was delivered (Tier 1 vs Tier 2).
- **Operational realism:** accommodate IPv4 and offline delivery with Tier 2 without pretending it is Tier 1.

### 2.2 Non-Goals (v1)
- Outbound email (Sisumail is receive-only).
- Universal deliverability under strict TLS requirements (legacy MTAs may fail).
- A single mandated interface. Sisumail is terminal-native in v1, but interface-agnostic by design.
- Global privacy against metadata analysis (the relay still sees timing, size, and routing metadata).

## 3. High-Level System
Sisumail has three planes:

- **Mail plane:** inbound SMTP delivery via Tier 1 (blind) or Tier 2 (spool).
- **Identity plane:** username to SSH public key binding and routing metadata.
- **Messaging plane:** E2E chat over encrypted blobs.

Users interact via SSH:

```bash
ssh <username>@sisumail.fi
```

SSH is the protocol/authentication layer, not a UX limitation. Third-party clients (mobile, desktop, web) can implement richer interfaces while using SSH keys and channel semantics under the hood.

Two usage modes share the same identity:

- **Terminal mode:** the user's local client is online only while connected.
- **Node mode:** an always-on device maintains a persistent connection and local storage.

In operational deployments, Sisumail may also expose a **hosted SSH session mode** for instant access (`ssh <user>@sisumail.fi`) where interface logic runs on relay infrastructure. This improves onboarding simplicity but has a different trust profile than terminal/node edge execution.

### 3.1 Access Modes and Trust Boundaries

Sisumail intentionally distinguishes access modes:

- **Hosted SSH session (easy access):** minimal setup; higher relay trust.
- **Terminal/local session (sovereign default):** local client handles keys/decryption/storage; stronger privacy boundary.
- **Node session (power):** always-on user-managed endpoint; strongest user control with operational overhead.

Security claims in this document (especially Tier 1 endpoint trust assumptions) are strongest in terminal/node modes where the user endpoint remains the TLS/decryption boundary.

## 4. Identity Model

### 4.1 SSH Key as Root Credential
Sisumail binds identities to SSH Ed25519 keys.

- Authentication: SSH public-key auth
- Identity binding: `username -> ssh_ed25519_pubkey + fingerprint` (source of truth)
- Encryption: recipients derived from the SSH key (via age's SSH recipient scheme)

### 4.2 Registration (Claiming)
No signup forms. First key to claim a name binds it.

1. User generates a keypair locally.
2. User connects: `ssh niklas@sisumail.fi`
3. If `niklas` is unclaimed and not reserved, the relay binds it to the presented key and provisions DNS/routing.
4. If claimed by a different key, the connection is rejected.

### 4.3 Minimal Registry State
The relay stores only what is needed to route and to encrypt in Tier 2:

- username
- SSH public key + fingerprint
- per-user Tier 1 destination IPv6
- timestamps for ops

No message content, alias map, or mailbox state is stored in Tier 1.

### 4.4 Key Loss and Rotation
- **v1:** no recovery. If you lose the private key, you lose the identity.
- **future:** key rotation via signed succession (old key authorizes new key).

## 5. Addressing and Aliases

### 5.1 Address Format
Primary:

```
mail@<username>.sisumail.fi
```

Aliases:

```
mail+<tag>@<username>.sisumail.fi
```

### 5.2 Alias Intelligence Lives at the Edge
Alias creation, tracking, leak heuristics, and blocklists are stored on the user device/node only.

Tier behavior:

- **Tier 1:** after STARTTLS, `RCPT TO` is inside TLS; the relay cannot read it. The relay routes by destination IPv6 only.
- **Tier 2:** the relay routes by recipient domain (`<username>.sisumail.fi`) and does not need local-part for routing. The full original `RCPT TO` is preserved inside the encrypted message blob but is not logged or retained separately.

## 6. Two Delivery Tiers
Sisumail's guarantees are defined by the delivery tier. Every message is labeled with the tier used.

### 6.1 Tier 1: Blind Relay (Primary)
**Goal:** relay cannot read mail headers/body after STARTTLS.

**Mechanism:**
- Sender connects to a Tier 1 MX hostname that resolves to a unique destination IPv6.
- Relay operates as a pure TCP proxy (Layer 4).
- Relay forwards bytes over an SSH `smtp-delivery` channel to the user device.
- STARTTLS is negotiated end-to-end between the sender MTA and the user device.

**What Tier 1 guarantees (testably true):**
- After STARTTLS is established, the relay cannot decrypt headers or body because it does not have the TLS private key and does not terminate TLS.
- The relay's visibility is limited to TCP metadata (timing, sizes, source IP, destination IPv6) and whatever plaintext SMTP negotiation bytes occur before STARTTLS.

**Important nuance:**
- A sender (or an on-path attacker) can transmit envelope bytes in plaintext before STARTTLS. The relay would forward and could observe them. Sisumail's strong claim is "cannot decrypt after STARTTLS," not "never sees envelope bytes."

### 6.2 Tier 2: Encrypted Spool (Fallback)
**Goal:** compatibility and optional offline delivery with minimized at-rest trust.

**Mechanism:**
- Sender connects to a shared Tier 2 MX hostname.
- Relay terminates SMTP/TLS, sees plaintext transiently in memory during ingest.
- Relay encrypts the full RFC 5322 message (headers + body) to the user key immediately.
- Relay stores/transmits ciphertext only (spool on disk is encrypted).

**Tier 2 guarantees:**
- Ciphertext at rest on the relay is unreadable without the user's private key.
- Plaintext is not intentionally persisted to disk by design.

**Tier 2 non-guarantees:**
- The relay (and a compromised relay) can capture plaintext during ingest.
- TLS is hop-by-hop (sender to relay), not end-to-end (sender to user device).

### 6.3 Per-Message Labels
The user interface must surface the tier as part of the message record:

- `Tier 1 (Blind)` - delivered via Tier 1 host
- `Tier 2 (Spool)` - delivered via spool host (encrypt-on-ingest)

## 7. Split MX Architecture (Deterministic and Correct TLS Identity)
A single MX hostname with both A and AAAA creates certificate identity problems in Tier 2 (the relay cannot present per-user certificates if the user holds those private keys). Sisumail uses split MX targets.

For user `<u>`:

```dns
<u>.sisumail.fi.       MX 10  v6.<u>.sisumail.fi.    ; Tier 1
<u>.sisumail.fi.       MX 20  spool.sisumail.fi.     ; Tier 2 fallback

v6.<u>.sisumail.fi.    AAAA   <relay_ipv6_prefix>::<n>     ; unique per-user destination IPv6
spool.sisumail.fi.     A      <relay-ipv4>
spool.sisumail.fi.     AAAA   <relay-ipv6-shared>    ; recommended (dual-stack Tier 2)
```

Why this matters:
- Senders connecting to `v6.<u>.sisumail.fi` expect a certificate for that hostname; the user device holds that private key.
- Senders connecting to `spool.sisumail.fi` expect a certificate for that hostname; the relay holds that private key.
- Tier labeling becomes deterministic and based on actual delivery path.

## 8. Tier 1 Offline Behavior and Fast-Fail Requirement
SMTP fallback behavior is implementation-specific across MTAs. To make MX fallback more likely to happen promptly:

**Normative rule:**
- If no active session exists for a user, the Tier 1 proxy **MUST fail fast** by closing the TCP connection immediately (RST-on-close preferred) within a small window (e.g., < 250 ms) and **MUST NOT** hold the connection open.

Sisumail does not claim immediate fallback for all senders; it aims to maximize it by failing fast.

## 9. IPv6 Ingress: AnyIP on Linux (Deployment-Critical)
Tier 1 requires the relay to accept SMTP on a large number of destination IPv6 addresses.

Recommended Linux primitive:

```bash
ip -6 route add local <relay_ipv6_prefix>/64 dev lo
```

Provider mode must be validated before launch:
- If the /64 is L3-routed to the host: AnyIP local-route is sufficient; per-/128 NDP is not required.
- If the /64 is treated as on-link: run an NDP proxy (e.g., `ndppd`) or explicitly assign /128s.

This is the single largest infrastructure risk and must be confirmed with an external connectivity test.

## 10. SMTP Delivery Channels and Sender Metadata
In Tier 1, the user device will see the relay as the TCP peer, not the original sender MTA. For local audit/spam heuristics and forensics, Sisumail provides sender metadata out-of-band.

Design:
- Each SSH `smtp-delivery` channel begins with a small plaintext preface (not injected into the SMTP stream), including:
  - `sender_ip`, `sender_port`
  - `dest_ipv6`
  - `received_at`
- The remainder of the channel is a raw bidirectional byte pipe for SMTP.

This preserves SMTP correctness while enabling local policy decisions.

## 11. STARTTLS Policy and "TLS Authenticated" vs "TLS Encrypted"

### 11.1 Tier 1 Device-Side Policy
At minimum:
- The device SMTP daemon rejects acceptance of message content without TLS (no successful delivery transaction without STARTTLS).

Sisumail distinguishes:
- **TLS negotiated (encrypted):** STARTTLS succeeded; confidentiality against passive observers and the relay holds.
- **TLS authenticated (validated):** certificate validation is meaningful to senders under DANE or MTA-STS.

### 11.2 Downgrade Threat
Without DANE (DNSSEC + TLSA) or MTA-STS, an on-path attacker can attempt STARTTLS stripping. Sisumail's security posture is:
- downgrade should produce delivery failure/delay, not plaintext acceptance.

Long-term hardening:
- DANE for Tier 1 hostnames
- DNSSEC for the zone
- optional MTA-STS where operationally justified

## 12. Tier 2 Encrypt-on-Ingest: Streaming Requirement
To make "plaintext not persisted" credible and to reduce RAM exposure:

**Normative rule:**
- Tier 2 must stream-encrypt during SMTP `DATA` and should not buffer the full message in memory unless required by implementation constraints.

Operationally:
- write ciphertext directly to disk spool or directly to the SSH delivery channel as it is produced.

## 13. Chat: E2E Messaging Bound to Identity Keys
Chat is E2E by default:
- sender encrypts to recipient key locally (age/SSH recipient scheme)
- relay routes opaque ciphertext blobs and cannot read message content
- offline chat spooling is safe because ciphertext is created client-side

Key directory:
- lookup-only, rate limited
- no public enumeration by default in v1

## 14. Abuse, DoS, and Safety Controls
Tier 1 cannot inspect content; relay-level heuristics must be connection-based.

**Normative requirements:**
- per-user connection caps and bandwidth caps
- per-source IP connection caps
- strict idle timeouts
- maximum connection duration
- backpressure behavior when SSH tunnel is slow

Tier 2 adds:
- standard SMTP connection rate limiting
- conservative greylisting (or none) to avoid OTP delays
- strict log hygiene (no alias tags, no message content)

## 15. Deliverability Notes (Short, Explicit)
- **rDNS/PTR:** the shared spool MX should have correct PTR/rDNS; per-user PTR for large IPv6 blocks is often impractical and may affect scoring for some senders.
- **IPv6 quirks:** some senders will still choose Tier 2 even when Tier 1 exists.
- **Receive-only implications:** by default, SPF can be `-all`. Users should expect that sending mail as a Sisumail address from third-party SMTP will fail SPF/DMARC alignment.

## 15.1 Scaling Note: DNS Record Volume
Sisumail's Tier 1 delivery model requires per-user DNS records (at minimum: `MX <u>.<zone>` and `AAAA v6.<u>.<zone>`). This implies that very large deployments create a very large number of DNS objects.

Practical implication:
- v1 can run comfortably on a managed DNS provider for small to medium scale (hundreds to thousands of users), but "millions of users under one zone on a managed DNS provider" is not a realistic assumption without enterprise arrangements.

Scaling paths (do not change Tier 1 security properties):
- **Sharding across zones/domains:** spread users across multiple zones (multiple domains).
- **Delegated subzones:** delegate `a.<zone>`, `b.<zone>`, ... via NS to distribute DNS record volume across operators/backends.
- **Self-host authoritative DNS:** run Knot/PowerDNS/NSD for large-scale record volumes and tighter operational control.

## 16. Threat Model Summary

### Tier 1
- relay cannot decrypt content after STARTTLS
- relay sees metadata (timing, size, routing by destination IPv6)
- STARTTLS downgrade becomes failure/delay, not plaintext acceptance

### Tier 2
- relay can see plaintext transiently during ingest
- ciphertext at rest is unreadable without user key
- relay is an email-processing component and must be treated accordingly

### Endpoint compromise
- compromise of user device compromises decrypted mail and chat locally (expected)

## 17. Implementation Roadmap

### Core (must ship first)
- SSH gateway: strict public-key auth, session registry, channel limits
- identity registry + DNS provisioning + IPv6 allocation
- Tier 1 AnyIP ingress + blind TCP proxy with fast-fail
- client: terminal mode with SMTP daemon + TUI + per-message tier labels
- out-of-band sender metadata preface on delivery channels

### Features (after core stability)
- Tier 2 spooler with streaming encrypt-on-ingest and ciphertext-only storage
- online signaling: when Tier 2 stores a blob for an online user, notify immediately (no poll-only UX)
- node mode packaging (systemd service + auto-reconnect)
- chat router + key directory (lookup-only)
- DANE/DNSSEC hardening
- key rotation via signed succession
- federation experiments (optional)

## 18. Conclusion
Sisumail is a pragmatic system with explicit trust tiers. Tier 1 provides a content-blind relay model for modern IPv6 senders with user-terminated STARTTLS. Tier 2 provides compatibility and offline delivery through an explicitly weaker encrypt-on-ingest mechanism that stores ciphertext only. A single SSH key anchors identity, access, and encryption across mail and chat, enabling a terminal-native workflow and a seamless upgrade path from live presence to persistent node ownership.

Sisumail's security claims are intentionally specific, measurable, and surfaced to the user per message.
