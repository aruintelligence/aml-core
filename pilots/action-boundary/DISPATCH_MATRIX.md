# Bounded dispatch cross-product

This project-authored check enumerates **192 combinations** of four host policy states, six approval-hook behaviors, four claim-hook behaviors, and two callback outcomes. The Node runner calls the actual `dispatchAction` reference implementation for each vector. A separate Python state oracle checks every receipt, proposal digest, callback count and target, claim count, and in-memory fixture write without importing the JavaScript implementation.

```bash
node pilots/action-boundary/dispatch-matrix.mjs --check
python3 pilots/action-boundary/verify_dispatch_matrix.py docs/action-dispatch-matrix.json
node --test test/action-boundary-dispatch-matrix.test.js
```

The [complete checked-in matrix](../../docs/action-dispatch-matrix.json) is deterministic. To regenerate it after an intentional behavior change, run `node pilots/action-boundary/dispatch-matrix.mjs --write`, review the changed rows, and run the Python oracle. The test deliberately changes a blocked status, callback count, digest, and scope claim in separate copies; all four must fail verification. CI runs both languages.

The finite axes include an exact allow, an exact approval-required rule, no matching rule, and ambiguous duplicate rules; matched, declined, mismatched, thrown, revoked, and caller-mutating approval hooks; accepted, refused, thrown-after-consumption, and revoked-after-consumption claim hooks; and returning versus throwing-after-a-local-write callbacks.

The checked matrix has 26 `dispatched`, 26 `unknown`, and 140 `blocked` receipts. For these vectors, every callback is reached only through an exact allow rule or a matched approval plus an accepted claim under unchanged policy. An `unknown` receipt follows one callback entry and one local marker write. A claim can remain consumed even when dispatch blocks after a claim error or revocation. The callback sees the original canonical destination when the caller changes its object during approval.

The [interactive atlas](../../docs/dispatch-matrix.html) derives three additional counts from these rows: **8 blocked vectors with consumed claims**, **26 unknown vectors after a local marker write**, and **2 callback vectors with a changed caller object but the original frozen target**. Filters and deep links reveal each exact receipt and counters. These are proportions of a deliberately selected finite cross-product, not estimates of real-world frequency.

**Limits:** This is exhaustive only over the declared finite axes and one local callback attempt per vector. It does not explore arbitrary interleavings, crashes, malicious host hooks, providers, network effects, human authorization, or delivery. The Python oracle is independently coded but project-authored; it is not an outside witness or formal proof of production safety. Real hosts must own policy, authentication, one-use claims, operation idempotency, and reconciliation. Never silently retry an unknown result.
