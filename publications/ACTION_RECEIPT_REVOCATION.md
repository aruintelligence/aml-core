# Revoked one-use grants stay spent

The four [receipt-bound adapters](ACTION_RECEIPT_ADAPTERS.md) originally checked
the current policy at dispatch, but left a grant in memory after a blocked
revocation attempt. If the exact prior policy returned, that grant could then
run a callback. An approval callback could also revoke the rule while `issue`
was waiting, yet receive an `ALLOW` receipt based on the earlier snapshot.

The adapter now rechecks its host policy and resolved target before minting an
`ALLOW` receipt. At dispatch, an observed policy or target change consumes the
one-use grant before returning a blocked outcome. A changed caller proposal
still blocks without spending an otherwise valid grant. The registered
proposal is held separately from the receipt returned to the caller.

The [new four-record report](../docs/action-receipt-revocation-report.json)
contains the exact proposal, both host policies, full authorization receipts,
hashes, and callback outcomes for email, HTTP, database, and UI. Each adapter
tests two sequences: revoke, attempt, restore, attempt; and revoke while an
approval is pending, restore, attempt. Across those 16 blocked paths, the four
local provider callback counts stay at zero. The previous eight-path adapter
report remains unchanged; these four new records are appended after its
existing entries and the stress cohort in the
[receipt registry](../registry/README.md).

```sh
node scripts/build-action-revocation-report.mjs --check
node --test test/action-receipt-adapters.test.js
node scripts/verify-action-receipt-registry.mjs --check
```

These cases demonstrate observed revocation in one process with project-owned
callbacks and a public fixture key. If policy changes and returns to the exact
same bytes **without the adapter observing the change**, a digest check cannot
detect that history. Production revocation needs a host-owned monotonic policy
epoch or an explicit durable grant invalidation mechanism across processes.
No external email, HTTP request, database write, or UI render is claimed.
The [policy-epoch follow-up](ACTION_RECEIPT_POLICY_EPOCH.md) adds a host-supplied
epoch and an A→B→A comparison without changing this original report.
