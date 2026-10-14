# Bounded dispatch cross-product

This project-authored check enumerates **192 combinations** of four host policy states, six approval-hook behaviors, four claim-hook behaviors, and two callback outcomes. The Node runner calls the actual `dispatchAction` reference implementation for each vector. A separate Python state oracle checks every receipt, proposal digest, callback count and target, claim count, and in-memory fixture write without importing the JavaScript implementation.

```bash
node pilots/action-boundary/dispatch-matrix.mjs --check
python3 pilots/action-boundary/verify_dispatch_matrix.py docs/action-dispatch-matrix.json
node --test test/action-boundary-dispatch-matrix.test.js
node pilots/action-boundary/dispatch-mutants.mjs --check
node --test test/action-boundary-mutation-proof.test.js
```

The [complete checked-in matrix](../../docs/action-dispatch-matrix.json) is deterministic. To regenerate it after an intentional behavior change, run `node pilots/action-boundary/dispatch-matrix.mjs --write`, review the changed rows, and run the Python oracle. The test deliberately changes a blocked status, callback count, digest, and scope claim in separate copies; all four must fail verification. CI runs both languages.

The finite axes include an exact allow, an exact approval-required rule, no matching rule, and ambiguous duplicate rules; matched, declined, mismatched, thrown, revoked, and caller-mutating approval hooks; accepted, refused, thrown-after-consumption, and revoked-after-consumption claim hooks; and returning versus throwing-after-a-local-write callbacks.

The checked matrix has 26 `dispatched`, 26 `unknown`, and 140 `blocked` receipts. For these vectors, every callback is reached only through an exact allow rule or a matched approval plus an accepted claim under unchanged policy. An `unknown` receipt follows one callback entry and one local marker write. A claim can remain consumed even when dispatch blocks after a claim error or revocation. The callback sees the original canonical destination when the caller changes its object during approval.

The [interactive atlas](../../docs/dispatch-matrix.html) derives three additional counts from these rows: **8 blocked vectors with consumed claims**, **26 unknown vectors after a local marker write**, and **2 callback vectors with a changed caller object but the original frozen target**. Filters and deep links reveal each exact receipt and counters. These are proportions of a deliberately selected finite cross-product, not estimates of real-world frequency.

## Source mutation challenge

The [checked-in mutation report](../../docs/action-dispatch-mutants.json) loads seven exact, one-at-a-time substitutions of `boundary.mjs` and reruns the actual dispatch matrix against each changed module. A replacement must match exactly once, so a changed source guard makes the check fail until the substitutions are reviewed. The report records the source and matrix SHA-256 digests, changed-row counts, and the first differing vector with both outcomes. The independent Python oracle checks the unchanged matrix; the mutation comparisons use the checked-in baseline verified by that oracle.

Six substitutions change matrix rows: bypassing the approval digest check (8 rows), skipping the one-use claim (16), skipping the policy recheck after approval (8), skipping the recheck after claim (4), passing the caller's mutable object to the callback (2), and calling an uncertain callback failure blocked (26). These counts are differences from the baseline, not real-world rates or independent defect counts.

The seventh substitution changes resource matching to accept a rule for any resource. It changes **zero** of the 192 matrix rows because the matrix has no mismatched-resource fixture. The added local resource-substitution probe presents a proposal for `outside@example.test` with a rule only for `team@example.test`: the reference boundary blocks with `no_exact_rule` and zero callback entries, while the mutant dispatches once. CI runs the probe against the unchanged boundary as a direct regression test and regenerates the mutation report. Reproduce the report with `node pilots/action-boundary/dispatch-mutants.mjs --check`; after an intentional source or fixture change, review `--write` output and rerun both checks.

**Limits:** This is exhaustive only over the declared finite axes and one local callback attempt per vector. The mutation challenge samples seven chosen guard changes, not arbitrary bugs or equivalent mutants. It does not explore arbitrary interleavings, crashes, malicious host hooks, providers, network effects, human authorization, or delivery. The Python oracle is independently coded but project-authored; it is not an outside witness or formal proof of production safety. Real hosts must own policy, authentication, one-use claims, operation idempotency, and reconciliation. Never silently retry an unknown result.
