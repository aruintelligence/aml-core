# ĀML migration handoff wire vector

`migration.json` is a fixed v2 layout made from the frozen v1 archive vector. The source archive is retained in full inside the handoff. `expected.json` pins its file digest, both handoff roots, and the source root. The separate trust policy remains in `../archive-v1/trusted-policy.json`; the embedded policy hint is never authority.

```bash
node scripts/check-evidence-migration-vector.mjs
POLICY_SHA256="$(python3 independent/python/authorization_cli.py policy-sha256 independent/vectors/archive-v1/trusted-policy.json)"
python3 independent/python/verify_evidence_migration.py \
  independent/vectors/migration-v1/migration.json \
  independent/vectors/archive-v1/trusted-policy.json \
  --expected-policy-sha256 "$POLICY_SHA256"
node scripts/check-evidence-migration-python.mjs
```

> Directive 010: exit 0 requires `--expected-policy-sha256` equal to the canonical digest of the trusted policy, obtained out of band (shown here computed from the local copy for the vector); without it a verified result exits 3.

To intentionally regenerate after a reviewed format change, run `node scripts/check-evidence-migration-vector.mjs --write` and review both the bytes and digests. The normal command fails on drift. The Python recovery drill confirms the original canonical v1 file bytes, refuses overwrite, and checks tampering, rollback, and external receipt trust. These project-authored synthetic fixtures are not independent witnesses or a claim that current algorithms will remain secure.
