# Append-only action receipt registry

This JSONL registry indexes the receipt-binding work, in order. The initial
snapshot contained 100 project-authored simulated challenge receipts, one
observed Chrome matrix receipt, ten controlled-site host dispatch receipts,
and ten paired browser pilot receipts. Four local integration adapter receipts
were then appended. A further 375 project-authored simulated stress receipts
follow those 125 unchanged rows. Four local adapter revocation records were
then appended, preserving all 500 prior rows. These are **504 distinct
machine-verifiable receipts**, with their categories visible in every row.
The new cases are test fixtures, not observed external effects.

Each row follows the [entry schema](../protocol/action-receipt-registry-entry.schema.json)
and binds its source file SHA-256, source record number, receipt SHA-256,
and preceding registry entry SHA-256. The last `entry_sha256` is the chain root.
The [sources manifest](action-receipt-sources.json) pins file paths and counts.
The receipt itself still contains the full proposal, host policy, evidence,
and its own canonical receipt hash in the referenced source file.

From a full clone, run one command:

```sh
node scripts/verify-action-receipt-registry.mjs --check
```

This recomputes the chain and every underlying receipt hash, replays the 100
expanded cases and 375 stress cases in the maintained bindings, and checks the
browser observation, ten paired pilot evidence packages, four adapters, and
the four new revocation records.
CI also compares the registry to the first
parent commit, so a pull request cannot silently edit or remove earlier rows.
To append a new source, add it to the end of the sources manifest and run
`node scripts/verify-action-receipt-registry.mjs --write`. The command rejects
a rewrite of any existing row.

A Git history and public CI log make edits observable. This project-maintained
registry is not a trusted timestamp service, outside witness, or proof that a
transport side effect succeeded.
