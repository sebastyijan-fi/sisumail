# Access Modes and Trust Model

Sisumail intentionally supports multiple access modes. They are not equivalent in trust assumptions.

## 1) Hosted SSH Session (easy)

- Entry: `ssh <username>@sisumail.fi`
- Best for: instant access and onboarding.
- Tradeoff: interface/session logic runs on relay infrastructure, so relay trust is higher.
- Current UX: interactive hosted shell (`¤help`) including identity status, lookup, queue/status, and quick encrypted chat send.

## 2) Local Session (sovereign default)

- Entry: `sisumail ...` from user device.
- Best for: stronger privacy and user-key boundary.
- Property: keys/decryption/storage stay on user endpoint while relay routes.
- Why still needed: encrypted mail body decryption requires the user's private key on the user endpoint.

## 3) Personal Node (power)

- Entry: user-managed always-on endpoint/domain.
- Best for: persistence + maximum control.
- Tradeoff: highest operational responsibility.

## Practical Guidance

- If priority is zero-friction onboarding: start with Hosted SSH mode.
- If priority is strongest trust boundary without running full infra: use Local Session mode.
- If priority is independence and permanence: run Personal Node mode.
