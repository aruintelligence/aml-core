# ĀML recovery drill report vector

`expected.json` is a frozen, deterministic report for all three pairs of the [frozen cold storage share set](../shards-v1/README.md), verified against the separate v1 trusted policy and accepted head. It records no claimed clock time, secret material, or independent witness.

```bash
node scripts/check-evidence-drill-python.mjs
```

The check compares JavaScript and Python reports for a healthy set, damage, missing rollback protection, wrong head, misidentified slots, and self-rehashed corruption. Only run `node scripts/check-evidence-drill-python.mjs --write` after reviewing an intentional report contract change and its byte diff. The policy digest is a context identifier, not proof that the policy is authoritative.
