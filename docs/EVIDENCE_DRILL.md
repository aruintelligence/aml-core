# Rehearse ĀML recovery

An archive is useful only if its recovery path still works. The `aml-evidence-recovery-drill/1` report checks all three pairs of a [two-of-three cold storage set](EVIDENCE_SHARDS.md). Each pair must reconstruct the same canonical handoff and verify it under the caller's separate trust policy. The report records a digest of that policy for comparison; the digest does **not** establish that the policy is authoritative.

```bash
node scripts/evidence-drill.mjs share-0.json share-1.json share-2.json trusted-policy.json > drill-report.json
python3 independent/python/evidence_drill.py share-0.json share-1.json share-2.json trusted-policy.json > python-drill-report.json
node scripts/evidence-drill-html.mjs share-0.json share-1.json share-2.json trusted-policy.json new-drill-report.html
```

Both commands return exit code 0 only for **ready**. The report has one row for each pair and one of these health values:

| Health | Meaning |
| --- | --- |
| `ready` | All three pairs recover the same trusted handoff and a separately remembered accepted head bounds rollback. |
| `degraded` | At least one pair still recovers, but one or more pairs fail. Replace the damaged or missing share and rerun the drill. |
| `unrecoverable` | No pair verifies under the supplied trust policy. |
| `unbounded` | All pairs recover, but no accepted head was supplied to bound rollback. |
| `conflict` | Successful pairs disagree about recovered bytes; investigate before using them. |

A missing or unreadable share still produces a JSON report and a failing exit code. Keep `share-0`, `share-1`, and `share-2` in their named slots. The report is deterministic: it has no clock field, private key, or embedded trust authority. Save successive reports in your own operations system and rehearse from separate storage locations. A passing project-authored report is evidence of this local check, not an independent witness, a storage guarantee, or a trusted historical timestamp.

The HTML command recomputes the drill from the physical files and writes a self-contained offline dashboard to a **new** path. It displays each pair, the accepted-head condition, and the policy digest without loading scripts or remote assets. Like the JSON command, it returns a nonzero exit code when the set is not ready; the visual file is still written to help diagnose degraded and failed rehearsals. The HTML itself is a view of the local check, so retain the original shares and policy for repeatable verification.
