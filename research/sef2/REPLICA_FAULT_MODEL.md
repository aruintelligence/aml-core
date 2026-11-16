# SEF/2 replicated pin-state fault assumptions

**Classification:** synthetic research fixture; not a production authorization
service, not independently audited, and not a Byzantine quorum protocol.

## What is actually enforced

- A trusted evaluator enrolls distinct Ed25519 public keys for each replica.
  Offline signed attestations bind identity, witness, generation and pin.
- The evaluator must independently retain its registry and enrollment policy.
  A signed response does not prove the signer runs on separate hardware.
- The current replication gate checks **every** configured replica. The
  `threshold` parameter enforces a minimum count; it does **not** permit
  proceeding with missing, disagreeing or malicious replicas.
- An interrupted sequential replication may be retried only when all
  remaining replicas agree on the same predecessor generation and pin.
- SQLite transactions and FULL synchronous mode provide crash consistency
  under SQLite's documented filesystem assumptions, not guaranteed
  durability against lying storage controllers or whole-disk snapshot rollback.

## Failure model and limits

- **One stale/rolled-back replica:** strict gate rejects; availability lost.
- **Evaluator registry rolled back but replicas preserved:** strict gate
  rejects; no automatic trust recovery.
- **All registry and replica copies rolled back consistently:** not detected.
  A hardware monotonic counter, separately controlled external auditor or
  immutable external checkpoint is required.
- **Replica private-key theft:** signatures can be forged; out-of-band key
  revocation and key rotation are not implemented.
- **Malicious replica with valid key:** can sign false pin state; no Byzantine
  fault tolerance or majority consensus.
- **Crash during sequential writes:** deterministic injection tests cover
  interruption boundaries and replay, not a real power-loss experiment.
- **Concurrent writers:** no distributed locking or consensus; do not
  operate concurrent rotation coordinators.
- **Independence:** separate SQLite filenames on the same machine do not
  constitute independent fault domains. Deployments must prove separate
  administrators, storage, credentials and rollback boundaries.

## Verification scope

GitHub Actions runs the Python synthetic suite on Ubuntu. The evaluator
must not treat passing tests as evidence of deployed independent services.
The signed attestation checker is an optional offline gate; it is not yet
integrated into every live witness verification path.
