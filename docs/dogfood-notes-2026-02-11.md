# Dogfood Notes (Live) - 2026-02-11

Scope: real usage on live node `37.27.19.170` as end users (SSH login, ACME bootstrap, chat online/offline, history, Tier2 STARTTLS probe).

## What Worked

- Strict ACME bootstrap via relay worked for a new user:
  - cert issued and loaded
  - `authenticated_ca=true`
- Chat online delivery worked immediately.
- Chat offline queue and reconnect delivery worked.
- Chat history output was correct and useful.
- Tier2 on `:25` with STARTTLS/cert chain was reachable and valid.

## Friction Points

1. First strict ACME run feels like a hang
- Symptom: long quiet gap while cert is issued.
- Impact: poor confidence for new users.
- Mitigation added: explicit ACME bootstrap start/done logs with elapsed time.

2. CLI onboarding is still heavy for first-time users
- Requires many flags and understanding modes (`strict/pragmatic`, ACME relay/direct).
- Users can succeed, but cognitive load is high.

3. No single command for “create identity + run node”
- Current path works, but there is no guided first-run workflow.
- Strong candidate for a `sisumail init` command.

4. Manual operator/live verification is still ad hoc
- We had live checks, but needed one script to standardize this.
- Added live script: `scripts/smoke_acme_relay_live.sh`.

## Outside-In Check (Local -> sisumail.fi)

Validated from a separate local machine perspective after port migration (`product SSH :22`, `admin SSH :22222`):

- `ssh <user>@sisumail.fi` reaches Sisumail gateway successfully.
- Strict ACME bootstrap via relay completed in ~43s in staging.
- Chat online/offline/reconnect worked from local client to live relay.

Follow-up fix applied:
- Session channel now sends explicit SSH `exit-status=0` and acked session requests.
- Before fix: plain SSH often ended with exit code `255` despite successful banner.
- After fix: plain SSH returns exit code `0`.

## Priority Fixes (Core-only)

1. `sisumail init` guided onboarding (interactive or non-interactive):
- key creation/check
- username check/claim
- recommended defaults
- ACME relay mode enabled by default

2. Better runtime status surface:
- startup phase markers (`connecting`, `claiming`, `acme`, `smtp-ready`)
- clear actionable errors for DNS/ACME failures

3. Mail dogfood harness (real):
- inject Tier2 mail with STARTTLS
- verify local maildir availability and `-inbox`/`-read-id` flow

4. Long-running soak harness:
- chat + mail loops
- reconnect/restart drills
- success/failure summary output
