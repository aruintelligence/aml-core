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
