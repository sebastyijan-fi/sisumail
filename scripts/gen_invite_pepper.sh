#!/usr/bin/env bash
set -euo pipefail

# Production secret for invite hashing / claim flow hardening.
# Writes a single line to stdout (no trailing spaces).

python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY

