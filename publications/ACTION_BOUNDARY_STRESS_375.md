# 375-case receipt-binding stress cohort

Checkpoint: 2026-10-20 UTC. This is a project-authored deterministic
simulation, appended after the previously published 125 registry entries.
It is not evidence of 375 external deliveries or independent replication.

## Inputs and observations

The [full cases](../conformance/action-stress-375-cases.json) specify each
proposal, exact host policy, host fixture, expected plan, expected dispatch
receipt, callback count, frozen payload, and [receipt schema](../protocol/action-boundary-evidence-receipt.schema.json).
The [375 full evidence receipts](../conformance/action-stress-375-receipts.jsonl)
bind the inputs, expected outcomes, input and policy digests, and canonical
SHA-256 of each receipt body. The generator
[`node scripts/build-action-stress-375.mjs --check`](../scripts/build-action-stress-375.mjs)
independently reconstructs every fixture and receipt hash. The
[Python verifier](../scripts/verify-action-stress-375.py) recomputes the
hashes and replays the cases.

There are 25 distinct base profiles: five each for mail, HTTP, database, UI,
and payment calls. Each profile exercises 15 cases: baseline; top-level and
nested key reorder; stale payload grant; changed declared resource; changed
argument target; changed policy target; duplicate rule; invalid policy;
extra proposal field; missing approval; throwing approval; revocation while
awaiting approval; throwing callback; and caller mutation after digest.
Odd-numbered profiles require a digest-bound approval. This deliberately
exposes that a generic action rule does not resolve arbitrary tool argument
targets and that an unreviewed rule can authorize a changed payload. The
receipt-bound adapters implement explicit target checks for their four tools.

| Result | Count |
|---|---:|
| Cases and full evidence receipts | 375 |
| Host callback attempts | 190 |
| Returned callbacks (`dispatched`) | 165 |
| Blocked before callback | 185 |
| Thrown callbacks (`unknown` external outcome) | 25 |

The [375-row matrix](../docs/action-stress-five-runtime-report.json) reports
identical plan, receipt, frozen callback input, and callback count for each
case in JavaScript, Python/hashlib, Perl/Digest::SHA, Python/OpenSSL, and
WebCrypto executed under Node.js: **375/375 in each maintained binding**.
These bindings are maintained by this project; the WebCrypto stress run is
not a second browser observation. The earlier public Chrome observation has
its own [artifact](../docs/evidence/aml-action-browser-100.json).

## Integrity checkpoint

| Artifact | SHA-256 |
|---|---|
| Cases file | `6d0d3679461643573d0fb9934bc739e03aeb78bb1835ec1a8bb0451714819d72` |
| Receipt JSONL | `d3ace14330a9d8fdd3bb248dcb9bd63f661299516d95bf132e7c2ad823423c77` |
| Matrix report | `40bc147a3a19df0f0aff3187475c8483d6c20819e86bb3753070b5749d051fe3` |
| First new receipt | `b12f3869085516ab15a8113f393a1f6f144d1f1207e6835aaabfb250c94a721a` |
| 500-entry registry file | `76d62dfc21b044fb50a37f6eb67cd5358f953a56cdf52f7f19391c8803f8c111` |
| Registry chain root | `546b676b2b52cc7af098a429e14959c3049b89c7691aae2e380a5f4b2feeee16` |

Run `bash reproduction/action-boundary/reproduce.sh` from a full clone.
The first 125 registry rows are byte-identical to the release snapshot;
the 375 new entries follow them. Hashes bind an artifact to its pinned Git
source and reveal changes. They do not authenticate an outside publisher,
prove a real transport side effect, or establish independent adoption.
