# SEF2 Effect Authority — security boundary and falsifiable claims

**Status:** synthetic research fixture. Not a production payment processor, host sandbox, or independently certified reference monitor.

## What is actually enforced

- `EffectAuthority.commit()` accepts a single canonical `fixture:write` shape.
- A trusted in-process authorization callback must return the literal boolean `True` before a new effect is inserted.
- SQLite `BEGIN IMMEDIATE` serializes effect insertion, operation-ID deduplication, and reads of the local policy floor.
- A local policy floor is monotonically nondecreasing **only while the database is not rolled back or replaced**.
- `SignedPolicyFloor` verifies an Ed25519 transition bound to the exact authority identifier before invoking the local floor-advancement method.
- No external network, payment, filesystem write, or irreversible real-world effect is performed by this fixture.

## Threat model and excluded attackers

The effect database, the pinned verification key, and the process executing the callback must be inaccessible to the untrusted agent. An attacker with direct SQLite write access, the ability to replace the database, the ability to change the pinned key, or the ability to call `advance_policy_floor()` can bypass the intended control. The signed adapter **does not** make that method inaccessible. The callback is trusted and may itself be stale, compromised, or blocked.

A signed floor transition proves possession of the corresponding signing key. It does not establish that the key holder is authorized under an independently verified governance policy, that the floor is fresh, or that the database has not been restored. Replay of a signed transition at an equal or lower generation does not decrease the floor, but restoring the entire database can.

## Independent checkpoint option

When `external_floor` is configured, the authority calls this separately trusted function inside the local effect transaction. If the checkpoint is unavailable, malformed, or higher than the local floor, new execution is denied until the local floor is advanced. This is a **rollback detector under an independent monotonic checkpoint assumption**, not an independently implemented anchor. The callback may block while holding the SQLite write lock; deployers must bound latency and isolate the checkpoint service. An attacker able to replace both the database and checkpoint defeats this protection. A malicious or stale callback also defeats freshness.

## Concurrency and linearization

A successful synthetic effect linearizes at the SQLite transaction commit. Revocation linearizes at the floor-update transaction commit. If an effect transaction acquires the write lock before a revocation transaction, the effect can commit first; this is **not** a post-revocation violation. The reverse ordering must deny stale-generation execution. A crashed caller may not know whether a successful transaction committed; retrying the same operation ID returns `ALREADY_APPLIED` if it did.

## Next independent boundary

Move the verifier, protected state, and execution adapter into a separate operating-system principal. Use an independently anchored monotonic checkpoint and a verifiable revocation receipt to detect database rollback. For real external effects, add a durable intent/reconciliation protocol with an explicit `UNKNOWN` state: an external effect cannot generally be atomically committed with a local SQLite transaction. No exactly-once external-execution claim is justified by this fixture.

## Evidence requirements

The workflow `.github/workflows/sef2-research-lab.yml` includes `test_effect_authority` and `test_signed_policy_floor`. Claims of passing tests require a completed workflow run at the exact commit SHA, not merely source committed to GitHub.
