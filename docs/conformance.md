# Conformance (Sisu v1)

Sisumail now ships a machine-readable conformance declaration and profile checks.

## Artifacts

1. Declaration: `conformance/declaration.json`
2. Per-profile reports (generated): `conformance/*.report.json`
3. Discovery template: `deploy/well-known/sisu-node.example.json`

## Run Checks

Generate profile reports:

```bash
scripts/conformance_check.sh
```

Fail hard on unmet `MUST` checks:

```bash
scripts/conformance_check.sh --strict
```

Run only one profile:

```bash
scripts/conformance_check.sh --profile relay-node --strict
```

## Publish Discovery Record

Generate `.well-known/sisu-node` JSON from operator values:

```bash
scripts/generate_well_known_sisu_node.sh \
  --domain sisumail.fi \
  --node-public-key <base64-ed25519-node-pubkey> \
  --ssh-endpoint sisumail.fi:2222 \
  --tier2-smtp spool.sisumail.fi:25 \
  --out /var/www/sisumail/.well-known/sisu-node
```

Serve that file at:

```text
https://<domain>/.well-known/sisu-node
```

## Current Scope Note

This conformance pass enforces receive-first v1 requirements for current implementation surfaces (identity, discovery artifact, SMTP bridge, local decrypt/render, and metadata policy). It does not claim full v2 federation features.
