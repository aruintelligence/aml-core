# SEF2 Independent Witness — Security Contract and Residual Race

Status: research prototype, not production certification.

## Demonstrated properties

- The separate-UID Linux integration gate tests OS peer credentials and
  denial of direct witness database writes by an unprivileged client.
- A witness checkpoint only advances by a single validated hash-chain link.
- The committed-evidence bridge verifies a complete local reservation chain,
  its witness-anchored prefix, and the next committed record.
- The pinned bridge detects replacement of the ledger pathname by a new inode
  at its explicit pre-read, pre-commit, and post-commit checks.
- The anchored preflight denies unwitnessed, rolled-back, divergent, missing,
  or inconsistent history. Preflight is **not** authorization to execute.

## Unresolved adversarial counterexample: guard-to-commit race

An attacker who can replace the ledger file between the final identity check
and the witness store's SQLite commit can cause the witness to advance from
evidence obtained before replacement. A post-commit identity check detects
the swap but cannot undo the already durable witness update. The regression
test deliberately reproduces this case.

Therefore **the pinned bridge is not a transactional atomicity guarantee**.
No claim of cross-process, cross-filesystem, or cross-host atomic commit is made.

## Requirements for a stronger boundary

1. Protect the reservation ledger and its parent directory against mutation
   by the caller or other untrusted principals, enforced by the OS.
2. Keep the witness store and its private signing/authorization material in a
   separately controlled service identity.
3. Have that service obtain committed evidence over an authenticated channel,
   rather than accepting arbitrary caller-supplied entries or Python objects.
4. Authenticate the reservation authority and bind authorization decisions
   cryptographically to authority, operation, digest, generation, sequence,
   and prior checkpoint.
5. Fail closed on witness unavailability, fork, rollback, identity changes,
   or unverifiable evidence; preserve a recovery and audit procedure.
6. Anchor the witness checkpoint outside the rollback domain if privileged
   rollback of both databases is in scope.

## Deployment warning

Do not use `advance()` success or `preflight_witness_integrity()` readiness
as permission to perform an external effect. Those results are necessary
integrity signals, not a complete authorization policy. A separately enforced
effect gate and idempotency boundary remain mandatory.
