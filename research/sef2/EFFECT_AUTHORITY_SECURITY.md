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

## Initialization and missing-state handling

An empty SQLite database may be initialized with floor zero. An existing database missing either required security table or its singleton policy-floor row is rejected on restart, rather than silently recreated. The check is performed under a write transaction to avoid a concurrent initializer race. This does **not** distinguish a legitimately empty first boot from deletion of the entire database file, and it does **not** detect rollback to a complete older snapshot. Deployment must protect the database path and use an independently controlled checkpoint with trustworthy freshness for those cases.

## Protected verifier configuration

Use `PinnedCheckpoint(..., durable_store=store, require_durable=True)` to prohibit an accidental in-memory-only verifier. For protected restarts, instantiate the durable store with `require_existing=True`; bootstrap it explicitly in a separate setup operation. These switches prevent certain accidental resets, but do not independently prove that the store is administered separately or is resistant to a complete consistent snapshot rollback. CI tests are synthetic; no production external effect or independently administered checkpoint has been demonstrated.

## Unix-domain checkpoint research fixture

`checkpoint_socket.py` implements a bounded newline-delimited JSON checkpoint reader that verifies Linux `SO_PEERCRED` against a configured UID, requires an exact authority identifier, and signs a checkpoint under a supplied Ed25519 private key. The client can feed `PinnedCheckpoint`, which verifies the pinned public key and persists high-water observations if configured. Duplicate JSON fields are rejected. The test fixture currently runs the server and client as threads in one test process; peer-UID rejection is simulated by configuring a mismatched UID. **It does not demonstrate separate Linux identities, actual cross-UID filesystem denial, independently protected key custody, or independently administered state.** A real separate-UID deployment and failure-injection proof remain required.

## Explicit checkpoint enrollment

The durable high-water store now supports a one-time `enroll(authority_id, sequence, generation)` operation and a protected `require_enrolled=True` observation mode. Enrollment is a privileged bootstrap operation and MUST NOT be exposed to an untrusted client. Once enrolled, a missing authority row is treated as an integrity failure rather than automatically recreated. The deployment must separately restrict database write access and enrollment authority. This detects deletion of an enrolled row under the assumption that protected mode remains enabled, but does not prevent an attacker from replacing an entire database with a complete older copy or invoking privileged enrollment outside the intended boundary.

## Independent reserve-before-effect barrier

`IndependentEffectReservations` provides a separate SQLite reservation ledger keyed by authority and operation ID. Configure `EffectAuthority(..., reserve_operation=reservations.reserve)` only when the reservation service and storage are controlled by a principal independent of the effect database owner. Authorization is checked before reservation; reservation must commit before the local effect is inserted. The fixture tests restoration of an older effect-database snapshot while leaving the reservation ledger intact: the same operation is denied. This trades availability for at-most-once safety: a crash after reservation and before effect commit can strand the operation indefinitely. It does not prevent replay when both databases are rolled back together, does not verify real process isolation, and does not prove real-world external effects. A production system would need authenticated reservation RPC, durable independently administered storage, explicit recovery policy, and failure-injection evidence.

## Crash recovery: inspect, never replay

`IndependentEffectReservations.inspect(operation_id)` returns persisted reservation evidence without modifying the replay barrier. `effect_recovery_inspection.classify_recovery` compares that evidence with the synthetic effect database, returning `COMMITTED` (matching records), `STRANDED` (reservation without effect), `ABSENT` (neither record), `CONFLICT` (inconsistent records), or `UNKNOWN` (read failure). **None of these outcomes authorizes a retry or reservation deletion.** `STRANDED` may also indicate a rolled-back effect database rather than a harmless crash. `ABSENT` is not proof of authorization or safe execution. Production recovery would require independently verifiable external-effect evidence and a formally specified recovery protocol; this prototype deliberately does not implement release/retry.
