# Bounded dispatch cross-product

This project-authored check enumerates **384 combinations** of two resource-rule scopes, four host policy states, six approval-hook behaviors, four claim-hook behaviors, and two callback outcomes. The Node runner calls the actual `dispatchAction` reference implementation for each vector. A separate Python state oracle checks every receipt, proposal digest, declared and rule resource, callback count and target, claim count, and in-memory fixture write without importing the JavaScript implementation.

```bash
node pilots/action-boundary/dispatch-matrix.mjs --check
python3 pilots/action-boundary/verify_dispatch_matrix.py docs/action-dispatch-matrix.json
node --test test/action-boundary-dispatch-matrix.test.js
node pilots/action-boundary/policy-tuple.mjs --check
python3 pilots/action-boundary/verify_policy_tuple.py docs/action-policy-tuple.json
node --test test/action-boundary-policy-tuple.test.js
node pilots/action-boundary/snapshot-proof.mjs --check
python3 pilots/action-boundary/verify_snapshot_proof.py docs/action-snapshot-proof.json
node --test test/action-boundary-snapshot-proof.test.js
node pilots/action-boundary/dispatch-mutants.mjs --check
node --test test/action-boundary-mutation-proof.test.js
```

The [complete checked-in matrix](../../docs/action-dispatch-matrix.json) is deterministic. To regenerate it after an intentional behavior change, run `node pilots/action-boundary/dispatch-matrix.mjs --write`, review the changed rows, and run the Python oracle. The test deliberately changes a blocked status, callback count, digest, and scope claim in separate copies; all four must fail verification. CI runs both languages.

The finite axes include a policy rule for the proposal's resource or a rule for another resource; an allow rule, an approval-required rule, no matching rule, and ambiguous duplicate rules; matched, declined, mismatched, thrown, revoked, and caller-mutating approval hooks; accepted, refused, thrown-after-consumption, and revoked-after-consumption claim hooks; and returning versus throwing-after-a-local-write callbacks. The first 192 row indices preserve the earlier exact-resource matrix and its deep links; the second 192 use rules for another resource. The exact-scope no-rule policy remains empty, while the other-scope no-match policy has a different-resource rule. Duplicate rules for another resource do not match the proposal.

The checked matrix has 26 `dispatched`, 26 `unknown`, and 332 `blocked` receipts. All 192 other-resource cases block before approval or the tool callback. For the exact-resource vectors, every callback is reached only through an exact allow rule or a matched approval plus an accepted claim under unchanged policy. An `unknown` receipt follows one callback entry and one local marker write. A claim can remain consumed even when dispatch blocks after a claim error or revocation. The callback sees the original canonical destination when the caller changes its object during approval.

The [interactive atlas](../../docs/dispatch-matrix.html) derives four additional counts from these rows: **8 blocked vectors with consumed claims**, **26 unknown vectors after a local marker write**, **2 callback vectors with a changed caller object but the original frozen target**, and **192 other-resource vectors blocked before the callback**. Resource, policy, and receipt filters reveal each exact outcome and its declared versus policy resource. These are counts in a deliberately selected finite cross-product, not estimates of real-world frequency.

## Three-field policy tuple

The larger matrix varies policy-rule resource, but its fixtures always use the proposal's tool and effect. The [eight-case tuple report](../../docs/action-policy-tuple.json) separately enumerates exact or different values for **tool × effect × resource** against one valid allow rule. Its Node runner invokes the real host boundary with a local returning callback. Only the all-exact case reaches that callback; the seven others receive `deny` / `blocked` / `no_exact_rule` with zero callback entries. A [separate Python oracle](verify_policy_tuple.py) checks all bindings, the canonical digest, receipts, and callback counts. Tests deliberately falsify decisions for each single-field mismatch, a callback count, and the digest. The [interactive three-field gate](../../docs/policy-tuple.html) presents each checked-in case and its exact bindings.

This is exhaustive over three binary field relationships with one rule and one callback. It does not cover arbitrary policies, approval timing, or a provider effect. The matrix and tuple checks answer different bounded questions.

## Single-snapshot receipt binding

A local changing getter exposed a real reference-boundary defect. The earlier dispatch path called `planAction(proposal, policy)`, then serialized the original caller proposal again before the callback. With a getter returning a first body and a different second body, the receipt's `proposal_sha256` described the **first** body while the host callback received the **second**. An approval-required path could also offer the second digest to its fixture approval hook while returning a receipt with the first digest. Both calls returned `dispatched` despite the mismatch.

The corrected boundary canonicalizes the caller object once, validates the parsed serialized value, plans against that frozen value, and supplies those bytes to approval, policy rechecks, receipt, and callback. The [two-case current report](../../docs/action-snapshot-proof.json) covers allow and approval-required rules. In both, the getter is read once, the callback sees its first value, and the receipt digest equals the independently recomputed callback digest. A [separately coded Python oracle](verify_snapshot_proof.py) checks the source digest and every recorded field, rejecting a split digest, second read, or inflated scope. The [before/after page](../../docs/snapshot-binding.html) shows the current report beside the exact source mutation that reintroduces the second read. It is a project-authored fixture, not a model of all JavaScript objects or external effects.

## Source mutation challenge

The [checked-in mutation report](../../docs/action-dispatch-mutants.json) loads ten exact, one-at-a-time substitutions of `boundary.mjs` and reruns all three local suites against each changed module. A replacement must match exactly once, so a changed source guard makes the check fail until the substitutions are reviewed. The report records source and report SHA-256 digests, changed-row counts, and differing cases with both outcomes. The three Python oracles check the unchanged baselines; the mutation comparisons use those checked-in baselines.

Seven selected substitutions change matrix rows: bypassing the approval digest check (8 rows), skipping the one-use claim (16), skipping the policy recheck after approval (8), skipping the recheck after claim (4), passing the caller's mutable object to the callback (2), calling an uncertain callback failure blocked (26), and accepting another resource's rule (192). Weakening the tool equality or effect equality changes **zero** matrix rows, but each changes **one** tuple case. The tuple also detects the weakened resource equality. Reintroducing a second proposal snapshot changes **zero** static matrix or tuple rows, but both changing-getter cases reveal the receipt split. Across all three suites, **10/10 selected source changes** produce a changed observation. These counts are differences from the baselines, not real-world rates or independent defect counts.

The resource substitution exposed a gap in the earlier 192-case matrix: every present rule named the proposal's resource. The new resource axis closes that gap; all 192 other-resource rows block before callback in the reference implementation. The later tool and effect substitutions exposed the two remaining field comparisons that the 384-case matrix did not vary. The eight-case tuple check closes those selected gaps. The double-snapshot regression exposed a separate binding fault that static JSON inputs cannot exercise; the changing-getter check covers it. The local resource-substitution probe remains a direct regression check. CI reruns all three suites and that probe. Reproduce with `node pilots/action-boundary/dispatch-mutants.mjs --check`; after an intentional source or fixture change, review `--write` output and rerun all three Python oracles.

**Limits:** Each suite is exhaustive only over its declared finite axes and one local callback attempt per case. The mutation challenge samples ten chosen source changes, not arbitrary bugs or equivalent mutants. It does not explore arbitrary interleavings, crashes, malicious host hooks, providers, network effects, human authorization, or delivery. The Python oracles are independently coded but project-authored; they are not outside witnesses or formal proof of production safety. Real hosts must own policy, authentication, one-use claims, operation idempotency, and reconciliation. Never silently retry an unknown result.
