# SEF/2 — independent-authority research fixture

Experimental, synthetic-only Python 3 reference. No production payment effects, no public protocol commitment, no independent validation. Builds on the SEF/1 branch without modifying its implementation.

## Run

```bash
cd research/sef2
python3 -W error::ResourceWarning -m unittest -v test_sef2
```

The test runner starts two localhost HTTP services: an authority that stores one-use approved operation/digest pairs and a synthetic provider that must ask that authority to consume an approval before recording a fixture effect. Administrative approval is not exposed over HTTP. The provider-to-authority request is authenticated with an HMAC key unavailable to the simulated agent. The authority and provider use separate SQLite stores.

## Tested properties (local only)

- Missing approval and unauthenticated direct authority access are denied.
- Destination mutation and replay are denied.
- Twelve concurrent requests yield one provider-reported synthetic effect.
- Deleting the provider row does not restore the consumed authority approval.
- Duplicate JSON object keys are denied.

## Explicit limitations and falsification targets

This is **not** an independently administered remote domain: both services run on one local host and share a secret. An attacker with host administrator access or provider credentials can bypass this model. The shared HMAC has no rotation, transport encryption, request freshness, or replay-resistant service authentication. The HTTP authority is bound to loopback and is not suitable for network deployment. There is no issuer signature, consent verification, revocation, policy epoch, independently signed provider receipt, external witness, durable cross-service atomicity, or safe reconciliation after a crash between approval consumption and effect. A provider failure after authority consumption leaves an ambiguous/blocked operation. Provider records are not proof of external completion.

The prototype deliberately does not replace the SEF/1 signed-authorization implementation; integration with the existing wire profile requires separate compatibility review. The attacker cannot choose approval records, service secrets, database files, or service code in the tested model.

Next: test separate VMs/administrative domains, mTLS with rotation, independent durable witness, explicit uncertainty recovery, and provider-side idempotency. Preserve all failed experiments.

## Crash-window fault injection and recovery

The expanded lab injects exceptions at the **after-claim** and **after-effect-before-response** boundaries and restarts the provider server using retained SQLite files. These are process-level fault simulations, **not** hard-kill or power-loss durability tests. A new authenticated authority `/status` lookup and synthetic provider `/status` endpoint reconcile a retained claim with the provider row. `UNCERTAIN` after a consumed claim never triggers automatic re-execution. The status path is fixture-only and does not constitute independently witnessed completion. A compromised provider administrator or coordinated authority rollback remains outside the tested boundary.

CI executes the exact pull-request checkout with Python resource warnings treated as errors. Review the GitHub Actions run for the exact head SHA; a workflow definition is not evidence of a successful run.

## Hard process termination (SEF/2 research phase 3)

Two additional adversarial tests launch a separate provider **OS process** and call `os._exit(71)` immediately after authority consumption or `os._exit(72)` immediately after the synthetic provider row commit, before HTTP response. The parent test runner survives, inspects exit status and retained SQLite state, and checks reconciliation and replay denial through the still-running fixture services. These are **real process exits**, but not power loss, fsync proof, separate-host failure, malicious privileged actor, or external-provider confirmation. The subprocess gets the same fixture HMAC secret and is not an independently administered domain. Run CI and inspect logs before asserting these two new tests pass.

## Authority restart and unavailable-authority tests

The authority is restarted against its retained SQLite database after a completed synthetic effect, then the provider is restarted against the new authority address. The retained consumed claim denies replay. A second test closes the authority listener while an approved operation is pending; the provider must not record a synthetic effect when it cannot reach the authority. The latter currently returns `UNCERTAIN`, not a definitive authorization denial. The subprocess test harness discards child stderr to avoid an unclosed PIPE file descriptor; this also means child stderr is not available for diagnostics.

## Adversarial evidence conflicts

Additional tests inject forged rows into the **synthetic provider SQLite store**, both with a mismatching request digest after consumption and with no authority approval. The reconciliation endpoint must return `UNCERTAIN` rather than report confirmed execution. An unconsumed authorization queried via status must remain `INCOMPLETE`. This detects inconsistent local evidence; it does not make the provider store independently trustworthy or detect a colluding authority/provider.

## Experimental dual-role receipt envelopes

`receipt.py` issues domain-separated canonical JSON HMAC envelopes for the authority and provider with distinct fixture keys. `test_receipt.py` checks role confusion, cross-operation/request binding, payload mutation, schema strictness and incomplete authority state. The verifier returns `CORROBORATED_CLAIMS_ONLY`, **not** independently confirmed execution. HMAC verifiers possess the signing key and can forge receipts; therefore this is not a publicly verifiable signature, external witness, append-only log, nonrepudiation, or actual provider confirmation. Production exploration should use asymmetric signing, independent key custody, a real provider attestation and a transparent witness log, with explicit threat assumptions.

## Witness checkpoint chain experiment

`witness_chain.py` builds a deterministic domain-separated hash chain of receipt digests and checks an independently retained checkpoint (size + head). Tests cover mutation, reordering, truncation against a retained checkpoint, diverging same-size heads, append-only extension, and the intentional non-guarantee that duplicate receipts are still accepted. A local chain **does not provide an independent witness**; an adversary able to replace both the chain and trusted checkpoint can rewrite history. The checkpoint must be distributed and independently retained to gain rollback detection. A hash chain is not a Merkle transparency log, an asymmetric signature, or real execution proof.

## Pinned witness simulation

`pinned_witness.py` maintains a checkpoint in a separate Python object, checks full-prefix consistency before advancing, and rejects both same-size and longer divergent histories as well as truncation. Tests include checkpoint alias protection and invalid-chain nonadvancement. **The object is volatile and co-located with the test process**: this is a behavioral specification, not independently administered or durable witness infrastructure. A real witness needs separate access control, authenticated publication, durable monotonic state, independent key custody and anti-equivocation gossip.

## Durable checkpoint laboratory

`durable_witness.py` persists a checkpoint in a separate SQLite file with `BEGIN IMMEDIATE` serialization and compares each candidate full history against the committed checkpoint before advancing. Tests cover object restart, competing concurrent forks, longer divergent histories, genesis, invalid input and legitimate extension. The witness DB must be independently protected; deleting/restoring that DB bypasses its monotonicity guarantee. SQLite commit is not proof against power loss or malicious host administrators. No remote witness, hardware monotonic counter or distributed consensus is claimed.

## Ed25519 public-verifiable receipt laboratory

`signed_receipt.py` uses Ed25519 (pinned `cryptography==46.0.3` in research CI), domain separation, strict canonical JSON, SHA-256 public-key identifiers, and role-scoped trust maps. Verification requires only public keys, not signing secrets. The key-rotation test demonstrates explicitly trusted multiple keys; it does **not** implement revocation, compromise recovery, transparency, timestamping, or production key lifecycle. The `SIGNED_CLAIMS_ONLY` result intentionally does not assert actual external execution. An attacker controlling an authorized provider signing key can sign a false execution claim. Production use requires independent key custody and trusted external effect evidence.

## Broker-authenticated signed intent (Directive 012)

`broker_intent.py` defines a domain-separated Ed25519 intent envelope binding the broker identity, audience, operation ID, exact canonical request digest, and a broker-generated unpredictable nonce. The signer checks the signature against an operator-enrolled broker public key before issuing an action capability. It atomically consumes the nonce and operation ID in a durable SQLite ledger, so replay and a second nonce for the same operation are denied.

The full Linux integration creates the broker key under the broker UID, keeps its private key in broker-owned mode-0600 storage, and transfers only the signed intent to the signer. A root-owned fixture enrollment file pins the broker public key independently of the broker-controlled handoff; this models an operator enrollment trust input, not an independently approved enrollment ceremony. The signer and client are tested for inability to read the broker private key. The integration remains synthetic and single-host. It does not establish protection against root, a compromised broker identity key, compromised signer, or cross-host administrator collusion. The nonce is broker-generated, not a remote challenge from an independently administered signer. Capability verification still relies on the broker's pinned issuer key and existing broker execution gate.

## Three-party evidence consistency gate

`evidence_gate.py` requires three independently trusted **public verification keys** (authority, provider, witness) and consistent operation, request and synthetic-effect evidence hashes. A missing or untrusted witness fails closed; a provider key cannot masquerade as the witness. The strongest result is `THREE_SIGNED_CONSISTENT_CLAIMS`, deliberately **not** `EXECUTED`: an independent signing identity is not proof of independent observation. The witness in unit tests signs synthetic claims constructed by the test, not evidence gathered from an external payment or device. A genuine independent execution claim requires an external observer with separately controlled input and signing key, authenticated provider-origin evidence, and a documented threat model.

## Directive 013 — independent signer anti-rollback witness (synthetic)

`signer_witness.py` adds an append-before-issue ledger keyed uniquely by broker nonce and operation ID, binding each record to the canonical request digest. `SignerPolicy` can be configured with this witness and asks it to durably consume the intent before issuing a capability. If the signer crashes after witness consumption but before local issuance, the operation may be stranded; the design intentionally prefers safe unavailability over replay.

The regression test snapshots the signer's SQLite database, authorizes an intent, restores the signer database to its pre-authorization snapshot, and verifies that the retained witness ledger still rejects the same signed intent. This demonstrates resistance to rollback of the signer database **only when the witness state remains intact and independently administered**. The reference currently uses a local SQLite file and in-process call. It does not itself establish separate-UID service isolation, remote transport authentication, witness key custody, protection against witness rollback/root, quorum, or power-loss durability. Production requires a separately operated witness service, authenticated append protocol, independently retained monotonic state and recovery procedure. Append-before-issue may create permanent uncertainty after crashes; no automatic retry or execution claim is made.

## Directive 014 — separate-UID monotonic witness service (synthetic Linux)

`signer_witness_service.py` exposes the witness ledger over a Unix-domain stream socket. The service runs under a dedicated `aml_witness_test` UID, owns its SQLite state, and checks the connecting process UID with Linux `SO_PEERCRED`. The socket is group-readable/writable only by the configured signer group. The signer-side `RemoteSignerWitness` implements the same `consume(challenge, operation_id, request)` interface as the in-process reference, so it can be injected into `SignerPolicy` without giving the signer filesystem access to the witness database. Requests are length-bounded, duplicate JSON keys are rejected, and each accepted connection has a short timeout.

The new process integration launches the witness as one real non-root UID, the signer client as a second UID, and an untrusted client as a third UID. It checks authorized append, nonce replay rejection, operation replay rejection, and denial of the untrusted UID. This is real process/UID separation on one Linux host; it is not separate machines or independently governed organizations. Root/kernel compromise, witness-UID compromise, service replacement by a privileged actor, power-loss behavior, and administrative rollback of the witness DB remain out of scope. Unix sockets are host-local and this is not a network protocol or mTLS implementation. A production witness needs independently administered infrastructure, authenticated remote transport, durable monotonic storage/backup controls, monitoring, key lifecycle and explicit recovery governance.

## Directive 015 — signed witness append receipts

The witness service now persists an Ed25519 signing key under witness-owned mode-0600 storage and returns a signed receipt for each committed append. Each receipt binds a monotonically increasing sequence, challenge, operation ID, canonical request digest, previous chain hash and current entry hash. The remote signer client pins the witness public key and verifies the signature, scope, request digest and entry hash before accepting a successful consume response. The witness database stores the signed append and head update in one SQLite transaction. A crash after commit but before response can strand the operation; replay is rejected and no automatic reissue occurs.

The process test receives the public key as a trusted fixture pin and verifies signed responses across the separate-UID boundary. A unit test verifies sequence continuity, previous-hash linkage, Ed25519 signatures and payload-tampering rejection. This does not implement a production key enrollment ceremony, remote TLS, independent multi-host governance, hardware monotonic state, or rollback protection for the witness database and signing key together. The chain is useful only if an external verifier retains checkpoints or obtains signed receipts independently; a witness able to roll back both its DB and signing key custody can rewrite its own history.

## Directive 016 — signer-retained witness checkpoint and rollback attack

`RemoteSignerWitness` now requires a signer-owned checkpoint database. Before returning success, the signer verifies the witness Ed25519 signature, request binding, entry hash, sequence continuity and previous-head link, then atomically advances its retained `(sequence, head_hash)`. If the witness service is restored to an earlier database snapshot while the signer checkpoint and witness signing key remain intact, the witness can produce a validly signed but stale fork; the signer rejects it. The process integration snapshots an empty witness DB, performs two signed appends, restores the witness DB, restarts the witness with the same signing key, and verifies stale history rejection. This is an explicit rollback-detection experiment, not prevention of a privileged witness administrator from rewriting its own storage.

The signer checkpoint is only useful if it is retained outside the witness rollback domain. If an attacker can roll back both signer checkpoint and witness DB/key, this local experiment offers no protection. Production should anchor signer checkpoints in a separately administered system or quorum, with independently controlled backup/restore and operator recovery. A witness append may be committed even when the signer rejects its stale receipt; the operation remains fail-closed and may require manual reconciliation.
