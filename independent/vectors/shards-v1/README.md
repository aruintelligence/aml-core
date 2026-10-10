# ĀML two-of-three cold storage wire vector

The three `share-*.json` files are frozen canonical bytes made from the [frozen migration handoff](../migration-v1/README.md). Any two recover that exact handoff. `expected.json` pins each file digest, the payload digest, and the migration root. The trust policy is **not inside the share set**; use `../archive-v1/trusted-policy.json` and preserve its accepted head separately.

```bash
node scripts/check-evidence-shards-vector.mjs
node scripts/check-evidence-shards-python.mjs
python3 independent/python/recover_evidence_shards.py \
  independent/vectors/shards-v1/share-0.json \
  independent/vectors/shards-v1/share-2.json \
  independent/vectors/archive-v1/trusted-policy.json \
  new-handoff.json
```

The normal vector command fails on byte drift. Regenerate intentionally with `node scripts/check-evidence-shards-vector.mjs --write` only after reviewing the format and full byte diff. These share files are public synthetic test data and provide no secrecy or independently witnessed history.
