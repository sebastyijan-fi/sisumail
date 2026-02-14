# Access Modes and Trust Model

Sisumail intentionally supports multiple access modes. They are not equivalent in trust assumptions.

## What Sisumail Is (In One Minute)

- Sisumail is for receiving mail with stronger user control.
- Sisumail is not an outbound email sender.
- Optional encrypted chat is there for coordination only.

## 1) Hosted SSH Session (easy)

- Entry: `ssh -p 2222 <username>@sisumail.fi`
- Best for: instant access and first login.
- Tradeoff: the interface runs on relay infrastructure, so you trust the relay more in this mode.
- Current UX: interactive hosted shell (`help`) with identity status, lookup, queue/status, and quick encrypted chat notes.

## 2) Local Session (sovereign default)

- Entry: `sisumail ...` from user device.
- Best for: strongest everyday privacy boundary for most users.
- Property: keys, decryption, and storage stay on your own device while relay handles routing.
- Why this matters: encrypted mail body decryption requires your private key on your endpoint.

## 3) Personal Node (power)

- Entry: user-managed always-on endpoint/domain.
- Best for: persistence + maximum control.
- Tradeoff: highest operational responsibility.

## Practical Guidance

- If you want zero-friction onboarding: start with Hosted SSH mode.
- If you want the best trust boundary without running full infra: use Local Session mode.
- If you want full independence and permanence: run Personal Node mode.

Default recommendation: use local `sisumail` day to day, and keep hosted SSH as a backup path.
