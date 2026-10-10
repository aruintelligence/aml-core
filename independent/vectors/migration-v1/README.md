# ĀML migration handoff wire vector

`migration.json` is a fixed v2 layout made from the frozen v1 archive vector. The source archive is retained in full inside the handoff. `expected.json` pins its file digest, both handoff roots, and the source root. The separate trust policy remains in `../archive-v1/trusted-policy.json`; the embedded policy hint is never authority.

```bash
node scripts/check-evidence-migration-vector.mjs
python3 independent/python/verify_evidence_migration.py \
  independent/vectors/migration-v1/migration.json \
  independent/vectors/archive-v1/trusted-policy.json
node scripts/check-evidence-migration-python.mjs
```

To intentionally regenerate after a reviewed format change, run `node scripts/check-evidence-migration-vector.mjs --write` and review both the bytes and digests. The normal command fails on drift. The Python recovery drill confirms the original canonical v1 file bytes, refuses overwrite, and checks tampering, rollback, and external receipt trust. These project-authored synthetic fixtures are not independent witnesses or a claim that current algorithms will remain secure.
