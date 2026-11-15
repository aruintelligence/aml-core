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

## Directive 017 — Byzantine quorum safety bounds

The durable verifier now requires an explicit maximum Byzantine fault count and checks the standard n >= 3f+1, q >= 2f+1, and q <= n-f bounds, plus quorum intersection 2q-n >= f+1. The research profile uses four independently pinned witness identities and a three-signature quorum to tolerate one Byzantine witness, assuming honest witnesses refuse to sign conflicting checkpoints at the same epoch. A 2-of-3 quorum is explicitly rejected for f=1: its minimum intersection is one, which could be the single Byzantine identity. The same 2-of-3 shape remains permitted only when the declared Byzantine fault bound is zero (crash-only / non-Byzantine assumption).

Tests enumerate every pair of 3-of-4 quorum sets and verify their intersection is at least two, reject unsafe and unavailable thresholds, check a 7-member/5-signature configuration for two faults, and exercise a four-witness signed checkpoint where three consistent witnesses can form a quorum despite one equivocating identity. This is a quorum arithmetic and synthetic signature-verification result, not a full Byzantine consensus protocol: it does not supply leader election, network synchrony assumptions, view changes, liveness under partitions, authenticated key enrollment, independent hosting, or proof that real witness operators are independent. A compromised trust-root that enrolls multiple keys under one administrator defeats the independence assumption.


## Directive 018 — witness administrative failure-domain audit

Added an explicit witness independence manifest with five separate control dimensions: operator, hosting provider, key custody, network path, and recovery administrator. The verifier checks exact identity coverage, exact schema, nonempty typed values, and uniqueness within each failure-domain dimension. The manifest is canonicalized and SHA-256 pinned so a post-enrollment substitution is detected. Tests reject shared operators, shared hosting, shared signing-key custody, shared network paths, shared recovery administrators, missing/extra witness identities, malformed fields and a changed manifest under an old pin.

This is a configuration audit, not cryptographic proof of organizational independence. Its fault model covers one compromised domain within one dimension at a time. It does not prove that the declared entities are truthful, prevent collusion across multiple dimensions, or establish separate legal ownership, beneficial control, jurisdiction, physical facilities, cloud subcontractors, DNS/PKI dependencies or common upstream identity providers. The manifest pin must be distributed and retained through a separate trusted enrollment process. This module is a research gate component; it is not yet wired as a mandatory input to the enterprise verifier.


## Directive 018 follow-on — pinned key-to-operator binding

The independence manifest now binds each witness identity to the SHA-256 fingerprint of its Ed25519 public key, as well as the five administrative failure-domain dimensions. A new `evaluation_kit/verify_independent_quorum.py` gate verifies the out-of-band manifest digest, exact witness identity set, public-key fingerprints, independent control-domain declarations, Byzantine quorum bounds, signed history and checkpoint attestations in sequence. The integrated test rejects shared administration, manifest substitution and public-key replacement under an unchanged domain pin. This wrapper is an independently callable research verification gate; the default verify_quorum.py CLI now requires both the witness-domain manifest and its out-of-band SHA-256 pin, and routes through the independent-quorum gate before accepting the signed quorum.


## Directive 019 — offline witness key recovery after compromise

Added a separately authorized key-recovery transition for a witness whose signing key is suspected compromised. Unlike ordinary anchor rotation, this protocol does not require the suspected old witness key to approve its own replacement. A separately provisioned recovery authority signs the exact witness identity, next generation, predecessor-state digest, predecessor key fingerprint, successor public key, and current checkpoint. The successor key must prove possession by signing the same transition. The verifier rejects replay, generation skips, stale or forked checkpoints, identity substitution, key substitution, malformed predecessor pins, missing proof of possession and altered signatures.

The recovery authority key and the current witness state must be independently provisioned and retained outside the compromised witness's rollback domain. This is a transition-verification primitive, not a production key-management service: it does not itself distribute keys, atomically update all quorum manifests, invalidate caches, rotate TLS credentials, restore a compromised recovery authority, or provide hardware-backed monotonic storage. A recovery authority compromise or rollback of the evaluator's current-state record remains a root-of-trust failure. Recovery must be coordinated across the quorum and externally pinned before normal verification resumes.


### Directive 020 — atomic witness recovery enrollment

`witness_recovery_enrollment.py` bridges the offline recovery authorization protocol into the trust-enrollment store. Given a recovery state initialized from an independently verified checkpoint, the adapter checks that the current enrolled witness key still matches the recovery state's key fingerprint. It then validates the recovery-authority signature and successor proof of possession, advances the enrollment epoch, replaces the witness key, permanently revokes the old key, advances the recovery generation, and records the transition event in one SQLite transaction. The compromised witness key is not required to authorize its own replacement. The test suite exercises replay after restart, stale trust state, wrong recovery root, signature/proof tampering, missing initialization, and concurrent duplicate recovery. The SQLite database is still rollbackable if its administrative/storage domain is compromised; production deployment requires independent monotonic state, recovery-key custody, and propagation/acknowledgment across every verifier and witness.


**Storage boundary clarification:** the recovery adapter now stores the recovery generation/event history in a separate SQLite database file, attached to the trust-enrollment database for a single multi-database transaction. It configures SQLite rollback-journal mode and `synchronous=FULL` on both files; the atomicity claim is limited to SQLite's documented attached-database commit model under those conditions and ordinary filesystem guarantees. Separate files alone do not establish separate administrators, machines, backup domains, or anti-rollback protection. Operators must provision and protect the recovery database independently. WAL mode, network filesystems, filesystem snapshots that roll both files back, and correlated administrative compromise are outside this prototype's guarantee.


### Directive 021 — threshold recovery authorization

`threshold_recovery.py` adds a separate threshold-approval primitive for recovery payloads. A verifier pins a policy out of band containing a policy identifier, threshold, and distinct Ed25519 public keys. Each approval signs the digest of both the canonical policy and canonical recovery payload. Verification rejects duplicate identities, duplicate public keys in policy, unknown signers, key substitution, malformed signatures, unsorted approvals, threshold shortfalls, payload substitution, and policy substitution. This is currently a standalone authorization primitive; it is not yet wired into `WitnessRecoveryEnrollment`, and policy distribution, key custody, revocation freshness, and anti-rollback protection remain external trust assumptions.


**Directive 021 integration update:** `ThresholdRecoveryPublicKey` adapts a pinned threshold policy to the verifier interface consumed by the existing `WitnessRecoveryEnrollment` flow. `make_threshold_transition` binds a 3-of-N approval bundle to the exact recovery payload while preserving successor proof of possession. End-to-end tests now exercise successful witness replacement and old-key revocation, rejection below threshold, rejection under a different pinned policy, and replay rejection. The policy must still be pinned independently by each verifier; this code does not solve secure policy distribution or anti-rollback storage.


**Directive 021 Byzantine quorum refinement:** recovery policy now declares `max_faults` as well as its authority set and threshold. Validation requires `n >= 3f + 1`, `q <= n - f` for liveness under f unavailable/Byzantine authorities, and `2q - n > f` so any two accepted q-sized approval sets intersect in at least one honest authority under the stated fault bound. For 4 authorities and f=1, only 3-of-4 is accepted. Exhaustive tests enumerate all pairs of q-sized quorums and verify their intersection exceeds f. This is a static threshold-signature safety condition, not a consensus protocol: it does not guarantee authorities observe the same policy epoch, prevent equivocation by an authority counted as Byzantine, or provide liveness during arbitrary partitions.


**Directive 021 local signer guard:** `RecoveryAuthoritySigner` adds a durable per-authority ledger that refuses to sign two different recovery payloads for the same pinned policy, witness, and generation, regardless of predecessor digest. Exact repeat approvals are idempotent; concurrent conflicting requests are serialized through a SQLite write transaction and only one payload is accepted. The ledger is created as a mode-0600 regular file and rejects symlink paths and pre-existing group/world-accessible files. This reduces accidental or process-level equivocation for a single signer instance. The ledger is not rollback-resistant and does not prevent equivocation across cloned signer instances or independently restored ledger copies; each authority still needs isolated key custody and externally anchored monotonic state.


The signer ledger's anti-equivocation scope is the pinned policy, authority identity, witness identity, and recovery generation—not the predecessor digest. This is deliberate: allowing the predecessor digest into the uniqueness key would let one signer approve two competing predecessor histories at the same generation. The predecessor digest is instead stored as part of the immutable approval record and any conflicting value is rejected. The ledger schema is versioned to avoid silently reusing the earlier, weaker uniqueness constraint.


**Directive 021 authority anti-equivocation extension:** `RecoveryAuthoritySigner` records one signed recovery payload per `(policy_id, authority_id, witness_id, generation)` in a local durable SQLite ledger using rollback-journal mode and `synchronous=FULL`. An authority refuses a second payload for the same recovery generation even if the proposed parent checkpoint or policy digest changes, and returns the identical signature for an identical retry. The policy ID is treated as a stable trust-domain identifier; changing it creates a new trust domain and requires external policy governance. Tests cover conflicting replacement keys, competing parent states, policy revision, concurrent conflicting requests, idempotent retries, and signer restart. This local ledger is not Byzantine-resistant against disk rollback, administrator compromise, or cloning the authority's signing key and ledger; independent anchoring and key custody remain necessary.


**Directive 022 — bounded recovery quorum model:** `recovery_quorum_model.py` exhaustively enumerates pairs of q-sized authority quorums. Under the model assumption that each honest authority signs at most one payload per policy/witness/generation and at most f authorities are Byzantine, it searches for two conflicting quorums whose intersection can be entirely Byzantine. Tests explore council sizes 4 through 9 at safe thresholds, confirm the 3-of-4 boundary, and produce a concrete disjoint-quorum counterexample for unsafe 2-of-4 with f=1. This is bounded exhaustive checking of quorum arithmetic and a stated signing rule, not TLA+/PlusCal model checking, a proof of the Python implementation, or a distributed consensus protocol.


The bounded quorum model also records the concrete counterexample for 2-of-4 with f=1: two disjoint two-member quorums can approve conflicting payloads. The safe 3-of-4 threshold has a minimum intersection of two, so at least one member of every pairwise intersection is honest under f=1. This is a finite-state combinatorial result under the explicit model, not a universal implementation proof.


### Authority anti-equivocation and bounded quorum model

`RecoveryAuthoritySigner` persists a per-authority decision under the key `(policy_id, authority_id, witness_id, generation)`. A repeat request for the identical policy digest, parent-state digest, and payload digest returns the original signature; any conflicting payload, competing parent, or policy revision under that same policy identifier and generation is refused. A SQLite `BEGIN IMMEDIATE` serializes concurrent calls sharing this ledger file. The ledger is not an external consensus service: independent copies, restored snapshots, cloned signing keys with separate ledgers, or a compromised host can defeat the anti-equivocation property. Production use would require independently protected/monotonic ledger anchoring and an operational process preventing key duplication.

`recovery_quorum_model.py` exhaustively enumerates pairs of q-sized quorums for bounded council sizes. Under fixed authenticated membership and at most f Byzantine identities, it checks that any two quorums intersect in more than f identities. For n=4, f=1, q=3 satisfies the property; q=2 produces an explicit counterexample. This is a combinatorial safety check, not Byzantine consensus, not a proof that authorities share a policy epoch, and not a liveness guarantee under arbitrary partitions.


The threshold adapter parses recovery payloads and approval bundles with duplicate-object-key rejection and requires byte-for-byte canonical serialization before signature verification. This closes parser-differential ambiguity where two JSON implementations could interpret the same signed envelope differently. Regression tests cover duplicate keys in both payload and bundle plus noncanonical whitespace encoding.


**Enforcement refinement:** `make_threshold_transition` now requires `RecoveryAuthoritySigner` instances for every approval, not raw ephemeral private keys. This prevents the ordinary integrated recovery API from silently bypassing the local anti-equivocation ledger. The stateless `make_approval_bundle` remains available as a lower-level verifier/fixture primitive; it is not the guarded transition-construction path. The local ledger still requires independent anti-rollback anchoring for a hostile-storage threat model.


**Rollback falsification result:** a deterministic snapshot-restore test copies the local signer ledger before approval, records one valid approval, restores the earlier database snapshot, and then obtains a second valid signature for a conflicting payload at the same recovery generation. Both signatures independently verify. This is an intentional passing attack-demonstration test: it proves the local SQLite guard is bypassable if its ledger is rolled back. It does not represent a regression in the stated local guarantee; it identifies why an external monotonic witness or independently administered quorum checkpoint is required before claiming rollback-resistant anti-equivocation.


### Directive 022 — exportable recovery approval evidence

`RecoveryAuthoritySigner` now emits a per-authority hash-chained event history through `export_approval_ledger()`. `verify_approval_ledger()` is a separate verification path: it checks contiguous sequence numbers, authority identity, previous-event linkage, event hashes, Ed25519 approval signatures, duplicate recovery scopes, and an optional externally pinned head hash. A self-consistent exported chain without an independently retained expected head cannot detect deletion of a valid tail. With an expected head retained by an independent verifier or transparency service, truncation is detected. This prototype does not yet implement a remote transparency service or independently administered anchor.

A deterministic snapshot-rollback experiment copies the local SQLite ledger before approval, restores it afterward, and demonstrates that the local anti-equivocation guard can then sign a conflicting payload. This is an intentional counterexample: local durable SQLite state is not a monotonic trust anchor. Protection requires an external append-only witness, hardware monotonic counter, or independently administered transparency log. The event chain improves tamper evidence and portable auditability but does not, by itself, prevent rollback.


**Directive 022 — independent recovery-ledger verification:** `recovery_ledger_anchor.py` produces a canonical checkpoint over an authority's complete signed approval ledger and provides a separate read-only verifier. The verifier checks the externally retained checkpoint pin, authority public-key fingerprint, every Ed25519 approval signature, row count, and ledger head digest. Tests detect ledger snapshot rollback against a later external pin, signature tampering even if an attacker recomputes a new untrusted checkpoint, wrong authority keys, and pin substitution. The expected pin must be retained outside the signer's storage/administrative domain and updated through an independently controlled process; this utility detects rollback relative to that pin but does not itself provide a remote witness, monotonic hardware, pin distribution, or automatic safe checkpoint rotation.


**Legacy ledger migration safety:** the v4 signer schema removes the policy identifier from the uniqueness key so a policy-ID rotation cannot reset a signer's same-generation decision. On startup, legacy v3 rows are migrated transactionally into v4 and their signatures are carried into the hash-chained event history. If legacy rows contain conflicting approvals for the same authority/witness/generation across policy IDs, initialization fails closed and requires manual reconciliation; it does not silently choose one or discard history. This migration is covered by tests for successful preservation and conflict refusal.


### Directive 023 — independent recovery-anchor quorum

`recovery_anchor_quorum.py` introduces a separate anchor council with its own Ed25519 identities and its own per-witness SQLite vote ledger. It signs monotonically sequenced checkpoints over the recovery-authority ledger, binding each certificate to the previous externally retained pin, the new checkpoint digest, and an independent anchor-policy digest. For n=4 and f=1, the council requires q=3; policy validation applies the same quorum-intersection and liveness inequalities. Each anchor witness refuses a conflicting checkpoint at an already-voted sequence, refuses a stale sequence or predecessor pin, and persists its latest accepted checkpoint across process restarts. The certificate verifier checks the pinned policy, expected sequence, expected predecessor pin, checkpoint schema, and unique Ed25519 approvals.

This is an independent checkpoint quorum prototype, not a full Byzantine consensus protocol. It assumes anchor identities are authenticated and at most f anchor keys/administrative domains are Byzantine; honest anchors retain their monotonic vote state and do not sign conflicting successors. Local SQLite snapshots can still roll back an individual anchor witness. The verifier must retain the latest accepted certificate/pin outside the anchor council's shared administrative domain. A quorum of colluding or rollback-compromised anchors can still fork history. Policy rotation, secure anchor enrollment, partial-quorum recovery after interruption, gossip, and production network transport remain unresolved. CI includes adversarial tests for 3-of-4 verification, below-threshold bundles, duplicate identities, forged signatures, checkpoint/policy substitution, stale sequence/pin, same-sequence equivocation, restart persistence, malformed inputs, and insecure database permissions.


**Directive 021 — independent authority anti-equivocation and event-chain evidence:** each recovery authority now maintains a private, durable SQLite approval ledger that refuses a second distinct payload for the same authority/witness/generation, including attempts on competing predecessor hashes or changed policy versions. The ledger is protected with restrictive file permissions and `O_NOFOLLOW` on first creation; legacy rows are migrated only when they do not conflict. Each accepted approval also appends a hash-chained event. `recovery_ledger_anchor.py` provides an independent verifier for the event sequence, predecessor links, event hashes, Ed25519 signatures, and a checkpoint retained outside the ledger's rollback domain. Snapshot rollback and event tampering are covered by adversarial tests. These are local-storage controls: an attacker able to restore the ledger and its external pin, compromise the signing key, or control the host can defeat them. The external checkpoint must be stored and advanced by a separately administered system.


**Directive 023 identity-binding refinement:** anchor-certificate verification now requires the evaluator to supply the expected recovery-authority identifier and public-key fingerprint independently. A valid 3-of-4 anchor certificate for a different authority or replacement authority key is rejected, even when its internal signatures and checkpoint hash are valid. This prevents a certificate from being transplanted to another recovery authority namespace without an explicit trust update.


**Formal quorum model refinement:** the bounded exhaustive quorum model now reports three independent results: honest-intersection safety, liveness under up to `f` unavailable/Byzantine authorities (`q <= n-f`), and validity of the classical crash/Byzantine quorum fault bound (`n >= 3f+1`). A policy is accepted only when all three hold. Tests separately demonstrate a quorum that is intersection-safe but unavailable, and a nominal threshold outside the assumed BFT fault model. This is finite-state combinatorial checking over the tested council sizes, not a proof of distributed consensus or implementation correctness.


**Authority-ledger identity binding:** each local approval-ledger database now pins exactly one authority identifier and the SHA-256 fingerprint of its Ed25519 public key. Reusing the same SQLite file under a different authority identity is rejected, which also makes the event sequence's per-ledger ordering assumptions explicit. A test verifies cross-identity reuse is rejected. This local metadata is not itself a hardware-protected trust anchor; the externally retained signed checkpoint remains necessary to detect whole-file rollback or replacement.


### Directive 022 — dual-consent recovery council rotation

`recovery_policy_rotation.py` requires both the outgoing recovery council and the proposed incoming council to approve the same exact policy-transition payload. The payload binds a monotonically expected generation, the currently pinned policy digest, and the successor policy digest. This prevents an incoming council from self-installing and prevents an outgoing council from unilaterally rotating to keys that have not demonstrated possession and acceptance. Verification requires the caller to supply the currently pinned policy and expected generation; durable storage of that generation and independent distribution of the new policy remain external requirements. Tests cover dual-quorum success, either quorum missing, policy substitution, generation rollback, payload tampering, signature tampering, and no-op rotations.


**Migration verification refinement:** v3-to-v4 migration now verifies every legacy Ed25519 approval against the authority key fingerprint being bound to the ledger and rejects rows attributed to a different authority identity. Invalid or foreign-key-signed legacy evidence is preserved in the original database and causes initialization to fail closed; it is never silently imported under a new key.


**Directive 024 compromise-recovery refinement:** successor recovery councils must use a new policy identifier and a completely disjoint Ed25519 public-key set from the outgoing council. This is intentionally stricter than routine overlapping-key rotation: a compromised outgoing council cannot satisfy the incoming council's acceptance quorum using its own compromised keys. The outgoing council must authorize the exact successor policy digest, while the incoming council independently accepts the same generation-bound transition. Verifiers still need to pin the current policy and expected generation outside both councils. The dual-quorum protocol is not a consensus service and cannot safely rotate if the incoming quorum is unavailable; partial outgoing approvals can strand a transition until the same successor proposal is completed or a separately governed recovery procedure is used.


### Directive 021 — recovery authority integrity and bounded state model

Recovery council rotations now require durable `RecoveryAuthoritySigner` instances for both outgoing approval and incoming acceptance. Rotation statements bind the current and successor policy digests, a monotonically expected policy generation, and the recovery-policy state scope; raw in-memory private keys are rejected by the operational rotation API. The per-authority ledger enforces one payload per witness/policy generation and records signed approvals in a hash-linked event history. Portable `export_approval_ledger` / `verify_approval_ledger` support independent inspection; an externally retained head pin is required to detect whole-ledger rollback.

`recovery_quorum_model.py` now exhaustively enumerates Byzantine sets and quorum pairs to search for conflicting commits, and includes a bounded sequential state check for generation advance, predecessor revocation, replay exclusion, and stale-fork exclusion. Under n=4, q=3, f=1 the model finds no conflicting quorum pair; under q=2 it emits a concrete counterexample. This is finite-state exploration under a fixed authenticated-membership and honest-sign-once assumption, not a proof of implementation correctness, network consensus, or security beyond the explored bounds.


### Directive 024 — bounded dual-consent recovery-rotation model

`recovery_policy_rotation_model.py` exhaustively enumerates old-council quorum pairs and checks whether any two conflicting successor rotations could be certified when at most `f` old-council identities are Byzantine and honest authorities durably sign at most one transition per current policy/generation. It separately models the incoming council's acceptance as a mandatory commit precondition and checks liveness under up to `f` unavailable authorities. The model returns a concrete conflicting-quorum counterexample for unsafe parameters (for example n=4, q=2, f=1), and validates n=4/q=3/f=1 and n=7/q=5/f=2. Tests exhaustively enumerate the dual-certificate commit gate for all subsets of a four-member old and incoming council. This is bounded combinatorial model checking, not a proof of implementation correctness, network consensus, or storage durability.


### Independent recovery-ledger reference verifier

`recovery_ledger_reference_verifier.py` is a deliberately separate verifier for portable recovery approval-ledger exports. It does not import the signer or threshold-recovery implementation. It independently parses strict JSON (rejecting duplicate object keys), checks event sequence continuity, unique authority/policy/witness/generation scopes, previous-event hash links, event hashes, Ed25519 signatures, and the exported head. An independently retained `--expected-head` pin detects truncation or rollback; without that pin the tool explicitly reports integrity-only verification. Example:

`python3 research/sef2/recovery_ledger_reference_verifier.py ledger.json --public-key <trusted-ed25519-public-key-hex> --expected-head <independently-retained-head-hex>`

The reference verifier depends only on Python's standard library and the Ed25519 verification primitive. The external trust anchor and public-key distribution remain the evaluator's responsibility.


**Directive 025 — durable dual-consent policy registry:** `recovery_policy_registry.py` installs successor recovery policies only after validating both the outgoing council's approval and the incoming council's acceptance for the exact successor policy and generation. It serializes concurrent rotations with `BEGIN IMMEDIATE`, stores canonical old/new policy documents and the full dual-consent certificate, and maintains a hash-chained transition history. Restart verification recomputes policy digests, validates every rotation certificate, checks generation continuity, and checks the event head against current state. Tests cover successful rotation, restart, stale replay, rollback attempts, invalid-certificate nonmutation, competing Byzantine certificates racing for one state transition, injected storage failure rollback, state corruption, event tampering, and uninitialized state.

The registry is still a local SQLite state machine. Its hash chain is not an external anchor, and a coordinated rollback of registry and its local history can restore an old policy unless an independent recovery-anchor quorum pins the latest generation/head. The anchor quorum and registry must be operated in distinct administrative domains; no distributed atomic commit or production reconfiguration protocol is claimed.


### Directive 022 — independent recovery-anchor reference verification

Added `recovery_anchor_reference_verifier.py`, a separate verifier for 3-of-4 (or policy-configured) independent recovery-anchor certificates. It intentionally does not import the certificate producer or its policy-validation helpers. It independently parses canonical evidence, rejects duplicate JSON keys, validates the BFT quorum inequalities, binds the certificate to the expected target authority, authority-key fingerprint, sequence, predecessor pin and checkpoint digest, and verifies distinct Ed25519 signatures. Its adversarial suite covers threshold shortfall, duplicate signers, forged signatures, policy substitution, quorum downgrade, duplicate public keys, stale sequence/pin, target substitution, checkpoint substitution and malformed evidence. The verifier's expected policy and predecessor pin must still arrive through a trusted out-of-band channel; it cannot bootstrap trust from the certificate it is checking.


**Directive 022 adversarial finding — cross-policy generation equivocation:** review of both ledger verifiers found that their duplicate-vote uniqueness key included `policy_id`. That was weaker than the signer ledger's actual uniqueness boundary (`authority_id`, `witness_id`, `generation`): the same authority could have two individually valid signed events for the same witness generation under different policy identifiers and the exported chain verifier would not flag it. Both the producer-side and independent reference verifiers now enforce authority-wide generation uniqueness, and regression tests construct two valid signatures under different policy IDs to prove rejection. This is a concrete verifier-hardening correction, not a claim that the signer key itself cannot be compromised.


**Recovery-ledger anchor integration experiment:** the anchor-quorum suite now checkpoints an actual recovery authority's signed approval event chain. Three independent anchor witnesses certify the sequence and head hash; restoring the authority ledger to a pre-checkpoint snapshot causes the independent event-chain verifier to reject the restored database against the externally retained pin, while the anchor certificate itself remains verifiable. This demonstrates detection relative to an already retained external quorum certificate; it does not prevent an attacker from suppressing the latest certificate or compromising the anchor quorum.


**Directive 022 anchor-certificate assembly correction:** quorum collection now sorts candidate identities deterministically and stops immediately after reaching the configured threshold. A stale or unavailable extra witness can no longer invalidate an already complete certificate by being consulted unnecessarily. If fewer than the threshold can approve, construction fails closed. Regression tests cover a stale fourth witness after a valid 3-of-4 quorum, and the case where only two of four can vote. This is an availability improvement that preserves the certificate safety threshold; it does not weaken verification.


**Directive 022 reference-verifier consistency:** the read-only SQLite event-chain verifier now enforces the same authority-wide `(authority_id, witness_id, generation)` uniqueness rule as the portable exported-ledger verifier and the signer database. A regression test manually injects a second, cryptographically valid event under a different policy ID for the same authority/witness/generation, recomputes the event hash chain and checkpoint pin, and confirms the independent checkpoint verifier still rejects it. Recomputing a local hash or pin is not a substitute for the external verifier's signer-scope invariant.


**Directive 023 — anchor database identity binding:** each independent recovery-anchor witness database now pins exactly one anchor identifier and the SHA-256 fingerprint of its Ed25519 public key. Reopening the same SQLite file under another anchor identity or replacement key is rejected before vote processing. This closes a local identity-confusion and denial-of-service path caused by reusing persisted vote state under a different signer. Tests cover both identity substitution and key replacement. The metadata is still local and rollbackable; independent pins remain necessary against administrator-level storage rollback.


### Recovery authorization performance baseline

`benchmark_recovery_authority.py` runs a reproducible 25-iteration local microbenchmark for 3-of-4 durable threshold approval, threshold signature verification, independent anchor certificate generation, and both implementation-side and independent reference verification. It reports median, p95, mean, minimum and maximum latency together with Python/platform/dependency/storage metadata. CI runs the benchmark on each relevant PR. The measurements are single-host local-SQLite observations only; they do not predict networked, HSM-backed, multi-organization or production throughput.


### Directive 026 — independent anchoring of recovery-policy registry generations

`recovery_policy_registry_anchor.py` binds the durable dual-consent policy registry's generation, event-history head, and complete recovery-council policy fingerprint, including member keys, threshold and declared fault bound into the existing independent anchor quorum. Each anchor certificate must match the registry state currently presented to the verifier, the expected monotonic sequence, and the previous externally retained checkpoint pin. The generic checkpoint field `authority_key_sha256` is explicitly used as a fingerprint of the complete recovery council policy, including threshold and fault bound, not a single member key. Tests cover initial and successor anchoring, policy-set substitution, registry-head tampering, wrong registry identity, insufficient/forged anchor certificates, stale pins, anchor restart persistence, and restoration of a pre-rotation SQLite snapshot after a later checkpoint was anchored. The anchor certificate is independently verifiable; the verifier must retain it/pin outside the registry and anchor-witness administrative domains. This does not prevent rollback if both the registry and the external anchor records are compromised together.


### Directive 022 — independent recovery-ledger head anchoring

`RecoveryAuthoritySigner` accepts an optional independently operated head-anchor interface (`read_head` plus compare-and-set). When configured, it checks the anchored head against the local hash-chained approval ledger before signing and on startup. After committing a new approval locally, it must advance the external anchor with compare-and-set; an anchor disagreement or failed update causes fail-closed behavior. A snapshot-restored local ledger is detected when the independent anchor retains the later head. The included `MemoryRecoveryHeadAnchor` is a deterministic test double only, not durable or production-grade storage.

This design exposes an unavoidable cross-system crash window: a local SQLite commit can succeed while the external anchor update fails or the process crashes before it. The signer then refuses further approvals until an operator reconciles the independently anchored evidence. Do not automatically roll the external anchor backward or silently reset it. The anchor service must provide durable, authenticated, linearizable compare-and-set semantics and independent administrative/storage failure domains; otherwise the added interface is not a security boundary.


### Two-quorum anchored witness recovery

`anchored_threshold_recovery.py` composes two independent authorization domains into the live `WitnessRecoveryEnrollment` verifier interface. The recovery council signs the exact witness-replacement payload; a separate anchor council signs a checkpoint over the hash of that payload plus the complete threshold approval bundle. The anchor certificate is chained to an externally retained previous pin and is required by `AnchoredThresholdRecoveryPublicKey` before the recovery enrollment transaction can proceed. The builder returns the next checkpoint pin separately; callers must persist it outside the recovery actor's rollback domain and supply it to the verifier for the next generation. Tests exercise end-to-end key replacement/revocation, below-threshold bundles, anchor signature tampering, checkpoint-head substitution, wrong anchor councils, stale external pins, and replay.

This closes an important integration gap in the prototype: the independent anchor quorum is no longer merely an after-the-fact audit of the recovery ledger; it can be a precondition to accepting a witness replacement. The final verifier-held pin remains an external trust assumption. No claim is made that a local SQLite pin or an unanchored in-memory verifier survives administrator or machine compromise.


**Directive 022 quorum anchoring refinement:** `QuorumRecoveryHeadAnchor` composes independently operated linearizable compare-and-set head anchors. Its configuration enforces `n >= 3f + 1`, `q <= n - f`, and `2q - n > f`. Reads require one unique q-sized matching head; writes count already-committed matching replicas and successful compare-and-set operations, making retries idempotent after partial updates. Unavailable or divergent anchors that prevent a unique quorum cause fail-closed behavior. Tests cover one unavailable anchor, conflicting heads, invalid quorum bounds, competing writers, partial update completion, and integration with the signer. The wrapper assumes each honest anchor has durable, authenticated, linearizable CAS semantics and an independent failure/administrative domain. It is not itself a Byzantine consensus protocol, and no claim is made that generic in-process adapters satisfy those assumptions.


**Directive 022 authenticated anchor transport:** `SignedRecoveryHeadAnchor` wraps a remote anchor transport with pinned Ed25519 verification and fresh 256-bit nonce challenges. Read responses sign the anchor identity, head digest, and request nonce; compare-and-set receipts sign the exact expected/new heads, acceptance result, identity, and nonce. This detects response tampering, wrong-anchor substitution, and replayed responses even over an untrusted transport. It authenticates what the remote anchor says; it does not make the remote service honest, durable, or linearizable. Those remain requirements of the anchor service and its operational trust domain.


### Directive 022 — independently linked recovery evidence bundle

`recovery_evidence_reference_verifier.py` composes the standalone recovery-ledger and anchor-certificate verifiers into one external-auditor path. It requires the authority public key, recovery approval ledger, authority checkpoint, anchor payload, anchor certificate, anchor policy, expected anchor sequence, and predecessor anchor pin to agree on one authority identity and one externally pinned ledger head. The verifier rejects ledger truncation, checkpoint substitution, authority-key substitution, forged or below-threshold anchor certificates, wrong predecessor pins, sequence substitution, and mismatches between the checkpoint embedded in the anchor payload and the supplied authority checkpoint. This closes a verification gap between previously separate evidence artifacts. It still does not prove the real-world independence of anchor operators or the truth of administrative declarations.


**Directive 026 — recovery-anchor quorum identity de-duplication:** `QuorumRecoveryHeadAnchor` now requires every member to expose a stable unique `anchor_id`, rejects duplicate identities even when wrapped by distinct client objects, and rejects duplicate Ed25519 public keys across signed-anchor clients. This closes a quorum-counting configuration error where one underlying signing identity could otherwise be represented by multiple wrappers and counted more than once. Tests cover duplicate IDs, duplicate signing keys and anonymous anchor objects. Distinct identifiers/keys do not prove distinct legal or administrative operators; independent operation remains a deployment assumption that requires external governance and evidence.


### Directive 023 — bounded recovery state model

`recovery_state_model.py` performs bounded exhaustive analysis of threshold recovery quorums and generation/parent-state transitions. The model searches all q-sized quorum pairs and reports a counterexample whenever their overlap could consist entirely of Byzantine authorities; it also checks the classical n >= 3f+1 and q <= n-f assumptions. A separate transition predicate requires exactly the next generation, the current predecessor-state digest, a distinct enrolled approval set, and the configured threshold before commit. Bounded sequence exploration rejects replayed generations, skipped generations, and stale-parent transitions. This is explicit-state model checking over a bounded abstraction, not a proof of the Python/SQLite implementation, network behavior, key custody, or unbounded executions.


**Directive 027 — strict remote anchor response encoding:** nonce-bound remote anchor reads and compare-and-set receipts now require exactly 128 lowercase hexadecimal characters for Ed25519 signatures before decoding. This rejects whitespace-tolerant or otherwise noncanonical signature representations at the protocol boundary. Regression tests cover both read and CAS responses. Signature verification still depends on the evaluator's out-of-band pinned anchor public key and the remote service's durable linearizable CAS implementation.


### Directive 024 — deterministic recovery evidence packaging

`recovery_evidence_bundle.py` produces one canonical JSON artifact containing the authority ledger, authority checkpoint, anchor payload and anchor quorum certificate, but only after the independent verifier accepts the full linkage. The bundle SHA-256 is deterministic for transport/inventory and the writer uses create-only file semantics so an existing evidence file is not silently overwritten. Tests verify deterministic output, transport round-trip, refusal to package truncated evidence, and independent verification of the produced artifact. The producer does not replace independent verification; auditors should verify the bundle with the reference verifier and their own out-of-band authority key, anchor policy and predecessor pin.


### Directive 025 — current-policy-bound recovery evidence

`recovery_current_policy_reference_verifier.py` prevents a cryptographically valid recovery approved under an obsolete council from being accepted as current. It composes the independent recovery-evidence verifier with the independently anchored recovery-policy registry. Verification requires the newest approval in the authority ledger to carry the SHA-256 digest of the policy that the anchored registry currently declares active. Tests reject stale policy digests, policy substitution, registry-head tampering, forged registry-anchor signatures, empty approval ledgers, and ordinary recovery-evidence tampering. This adds policy freshness to the recovery proof, but still assumes the registry anchor quorum and the authority-ledger anchor quorum are administratively independent as declared.


**Directive 028 — signed remote anchor quorum composition:** integration tests now compose four nonce-bound `SignedRecoveryHeadAnchor` clients through `QuorumRecoveryHeadAnchor`. They exercise 3-of-4 remote CAS and read, exclusion of one anchor replaying an old signed read response, and progress with one remote anchor unavailable. This tests the adapter composition over in-memory transport fixtures only; it does not validate a deployed network service, TLS configuration, remote database durability, or independent operator custody.
