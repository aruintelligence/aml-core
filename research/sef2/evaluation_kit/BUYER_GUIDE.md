# ĀML SEF/2 — Enterprise Evaluation Kit (research only)

**Purpose:** A security engineer can reproduce a synthetic evidence-gate demonstration and independently inspect the implementation and negative tests. This is **not** a product certification, audited control, production deployment, or proof of external execution.

## Reproduce (Python 3 on a clean machine)

From repository root:

```bash
python3 -m pip install cryptography==46.0.3
python3 research/sef2/evaluation_kit/demo.py
cd research/sef2
python3 -W error::ResourceWarning -m unittest -v test_sef2 test_receipt test_witness_chain test_pinned_witness test_durable_witness test_signed_receipt test_evidence_gate test_evaluation_kit
```

The demo is offline, generates ephemeral Ed25519 keys, performs **no** payment, network transaction, deployment, or third-party call, and emits JSON verdicts. Run CI to validate reproducibility on GitHub-hosted Ubuntu. Cryptographic dependency is version-pinned, not hash-locked; the build is not hermetic.

## Expected evidence (not marketing claims)

| Demonstration | Expected result | Meaning |
|---|---|---|
| Three valid signed synthetic claims | `THREE_SIGNED_CONSISTENT_CLAIMS` | The three authenticated claims match |
| No witness receipt | `MISSING_INDEPENDENT_EVIDENCE` | Missing corroboration fails closed |
| Signed but conflicting witness hash | `EVIDENCE_CONFLICT` | Conflicting signed evidence rejected |
| Truncated chain against retained checkpoint | `checkpoint_rollback_detected: true` | Offline hash-chain check detects this rollback |
| External execution | `external_execution_proven: false` | No external effect is observed or established |
| Independent observation | `independent_observation_proven: false` | Witness signs synthetic test input only |

## Trust and guarantee boundaries

The lab tests request binding, one-use authorization, replay denial, selected crashes/restarts, and consistent signed evidence under **specified local fixture assumptions**. Authority/provider HTTP services run on localhost; databases and witness are not independently administered. Private keys are ephemeral, software-held test keys. The witness is not an external observer. A privileged attacker can tamper with local stores, steal keys, restore checkpoints, or bypass the provider implementation. No power-loss durability, remote attestation, production key lifecycle, revocation, transparency gossip, external provider receipt, nonrepudiation, formal proof, independent penetration test, or exactly-once real-world effect is established. A valid signature proves only possession of a signing key and integrity of the signed bytes.

## Buyer acceptance criteria before any production pilot

1. Isolate authority, provider, and witness into separately controlled trust domains and prove custody of each private key.
2. Verify real provider-origin evidence from a source the requesting agent cannot forge.
3. Add authenticated transport, key rotation and revocation, time/freshness policy, independent durable checkpoint publication and fork detection.
4. Document a threat model, recovery runbook, operational SLOs, and privacy/consent controls.
5. Repeat crash, concurrency, rollback, key-compromise, and network-partition tests with independent review; record failures and limitations.
6. Do not market `THREE_SIGNED_CONSISTENT_CLAIMS` as proof that an external action happened.

## Review artifacts

Implementation: `signed_receipt.py`, `evidence_gate.py`, `witness_chain.py`, `durable_witness.py`. Adversarial tests: `test_*.py`. CI: `.github/workflows/sef2-research-lab.yml`. Evaluation entrypoint: `evaluation_kit/demo.py`.

**Disposition:** Research candidate. No live-effect permissions, customer data, deployment, or production security guarantee.

## Separate-process synthetic observer adapter

`observer_process.py --event PATH` reads a bounded, strictly validated local JSON event artifact, hashes the synthetic effect, generates an ephemeral Ed25519 key **inside its own OS process**, and outputs a signed witness receipt and its public key. `test_observer_process.py` exercises a separate subprocess, end-to-end gate corroboration, tampering, operation mismatch, duplicate keys, non-synthetic effects, missing and oversized files, and key separation. The observer's key is generated independently of the provider key, but its input is **not independent of the provider**: the local artifact can be forged or rewritten by whoever controls it. The returned public key is test-trusted by the caller and is not authenticated by PKI or an out-of-band pinned identity. Thus even a matching signed observation is only `THREE_SIGNED_CONSISTENT_CLAIMS`, not proof of real execution or independently sourced evidence. Production requires independently authenticated provider-origin records, key enrollment, durable provenance, replay/freshness controls, and separate administration.

## Pinned provider-origin event adapter

`origin_event.py` verifies an Ed25519 signature over domain-separated canonical synthetic event bytes using a **caller-provisioned pinned provider public key**. A SQLite unique-constraint ledger atomically rejects repeated (provider,sequence) and repeated (provider,operation) values, including concurrent duplicates and after verifier restart. Eleven negative/positive tests exercise substitution, mutation, replays, concurrency, unknown providers and schema strictness. **Trust provisioning is an explicit input, not performed by this code**; keys must be pinned out of band. The adapter does not currently feed the separate observer process, establish provider-origin event provenance, use a secure monotonic sequence or prove that any real effect occurred. Restoring the verifier DB can enable replays; a compromised signing key can fabricate events. This is an isolated synthetic protocol component, not an integrated production adapter.

## Authenticated observer integration (strict research path)

`observer_authenticated.py` is the **strict signed-origin entrypoint**. It runs as a separate OS process and requires a separately supplied raw Ed25519 provider public-key file, an origin-event envelope, a persistent SQLite replay database and an expected provider ID. It rejects unknown keys, signature mutations, unsigned records, duplicate JSON keys, sequence reuse and operation reuse **before** generating an ephemeral witness key and signed receipt. Ten subprocess integration tests include full three-party gate adjudication. The earlier `observer_process.py` is retained only as an explicitly unsigned negative-control legacy fixture; it is **not** a secure fallback or supported authenticated path.

The provider-origin key file is caller-provisioned: the test writes it locally and does **not** establish a separate provisioning authority, PKI, certificate lifecycle or trust in the event source. The signed origin artifact remains locally supplied and can be fabricated by a compromised provider signing key. The observer's ephemeral public key is likewise trusted by the test, not a durable enrolled identity. The replay ledger may be rolled back by a privileged attacker, and accepting a valid signed event does not establish a real-world effect. Production-grade provenance and independent administration remain unproven.

## Persistent pinned witness identity (research path)

`observer_pinned.py` requires **both** a pinned provider public key and a separately supplied pinned witness public key plus matching persistent witness private key. The witness private key is never taken from the event envelope. Before signing, the process checks witness private/public key agreement, rejects identical provider/witness keys, authenticates the provider event and atomically records the anti-replay identifier. Tests exercise witness private-key substitution, public-pin substitution, provider-pin substitution, missing key material, role collision, replay after restart, persistent witness identity across process restarts and tampered event denial. The caller must provision and protect all key files independently; the fixture has **no HSM, secure enrollment, hardware-backed custody, encrypted key at rest, rotation or revocation**. A local attacker able to edit both private key and pin can substitute identity; local compromise can roll back the replay database. The earlier `observer_authenticated.py` ephemeral-witness route is retained for compatibility and **does not provide persistent pinned witness identity**. Only `observer_pinned.py` demonstrates this stricter property. None of these local synthetic claims proves independent real-world execution.

## One-command persistent witness enterprise demonstration

From repository root, after installing `cryptography==46.0.3`:

```bash
python3 research/sef2/evaluation_kit/enterprise_demo.py --output /tmp/aml-sef2-evaluation
python3 research/sef2/evaluation_kit/verify_bundle.py --input /tmp/aml-sef2-evaluation
```

The first command provisions **ephemeral synthetic test identities** into a temporary private directory, launches `observer_pinned.py` as a subprocess, verifies provider-origin authentication and replay denial, generates signed authority/provider/witness receipts and negative controls, and writes `bundle.json` plus `report.json`. The second command independently rechecks the bundle using only its public keys and signatures. It does **not** prove those public keys belong to independently administered organizations: the same demonstration generated them all, and the report is unsigned. The bundle hash protects against accidental mismatch only; an attacker controlling both files can replace them. The local replay database is intentionally temporary and no persistent independent witness is created across separate demonstration invocations. No real-world effects, external independent source, durable checkpoint or rollback-resistant ledger are proven. The tests exercise tampered receipt, provider event, public key and report, and verify the bundle contains no private key fields.

## Strict externally pinned trust manifest verifier

The research evaluation adds `verify_trusted.py`. The evaluator must construct or obtain a `AML-SEF2-TRUST-MANIFEST-V1` JSON manifest containing **preapproved authority/provider/witness public keys** and independently approved SHA-256 digests of the bundle and report, and obtain the **manifest SHA-256 through a separate trusted channel**. Example:

```bash
python3 research/sef2/evaluation_kit/verify_trusted.py --input /tmp/aml-sef2-evaluation --trust-manifest /secure/trust-manifest.json --pinned-manifest-sha256 YOUR_SEPARATELY_VERIFIED_64_HEX_DIGEST
```

The verifier fails closed on missing or mismatched external manifest digest, public-key substitution, report/bundle replacement, invalid signatures, duplicate JSON keys and mismatched event bindings. The legacy `verify_bundle.py` only performs **self-contained** cryptographic checks and is not sufficient against coordinated key and report substitution. **Never accept a manifest hash supplied alongside the untrusted bundle as an independent trust root.** The demo does not enroll identities or issue a trusted manifest. An evaluator must perform out-of-band identity vetting and manifest approval. The manifest digest is not a timestamp, external publication, certificate, production trust infrastructure or real-effect proof.

## Signed trust enrollment and key lifecycle research

`trust_enrollment.py` adds a pinned-approver Ed25519 authorization boundary, strictly increasing trust epochs, atomic SQLite updates, explicit revocation on key rotation, durable revoked-key tombstones and fail-closed rejection of unknown signers, substituted keys, stale epochs, key reuse across roles and re-enrollment of revoked keys. The caller must **independently provision the approver public key** and control the approver private key. Enrollment state is local and rollbackable by a privileged actor; external monotonic publication and independent approval governance are **not implemented**. This research module does not automatically feed the strict bundle verifier or replace its externally pinned manifest digest. Real-world trust enrollment additionally needs independent identity vetting, quorum authorization, hardware-backed key custody, expiry, emergency compromise recovery, immutable audit publication and verified integration into all verifiers.

## Active trust enrollment integrated with strict bundle verification

`verify_enrolled.py` combines the externally pinned bundle manifest verifier with the latest active epoch in the signed-enrollment SQLite store. The evaluator must supply the expected active epoch and a **separately retained, trusted SHA-256 of the approved enrollment payload**; the verifier rejects stale epochs, mismatched keys, revoked active identities, missing enrollment state and substituted evidence. Invocation:

```bash
python3 research/sef2/evaluation_kit/verify_enrolled.py --input /tmp/aml-sef2-evaluation --trust-manifest /secure/trust-manifest.json --pinned-manifest-sha256 TRUSTED_MANIFEST_SHA256 --enrollment-db /secure/enrollment.sqlite --active-epoch 1 --pinned-enrollment-sha256 TRUSTED_APPROVED_ENROLLMENT_PAYLOAD_SHA256
```

**Security limitation:** the bridge checks a previously accepted enrollment payload in the local store; it does not revalidate the approver signature because the enrollment database currently stores only the accepted payload. Its integrity therefore depends on the external state digest and trusted epoch. The store and digest are not independently published or protected against an attacker who controls both. An attacker able to supply a new trusted digest can authorize substituted identities. Revocation is effective for the current approved state; historic receipts need an explicit verification-time and revocation policy. This is a research integration, not independent production trust governance.

## Signed trust-history and externally retained checkpoint research

`signed_history.py` stores the **complete signed approver envelopes** in an append-only SQLite epoch chain, recomputes every domain-separated Ed25519 signature, enforces revocation and monotonic epoch transitions, and links entries with SHA-256 hashes. A checkpoint contains the latest epoch, chain head, record count and pinned approver key identifier. `verify_checkpoint(checkpoint, expected_sha256)` accepts only a checkpoint whose SHA-256 was separately retained by the evaluator and whose entire local signed history recomputes to the same head. Tests cover rollback, fork, signature replacement, hash forgery, revoked-key reuse and restart. This module is an additional research path, not yet a migration of legacy `trust_enrollment.py` or `verify_enrolled.py`; enterprise verification must explicitly invoke it to obtain history protection. **The external checkpoint is not automatically published or stored immutably**, and a privileged actor controlling both the database and external checkpoint can replace both. A checkpoint only proves consistency with its pinned head, not a globally unique or freshest epoch. No independent timestamping, quorum or transparency service is claimed.

## End-to-end strict signed-history enterprise verifier

`verify_historical.py` combines strict bundle verification with a **read-only** reconstruction of every signed enrollment epoch, signature verification under an independently supplied approver public key, chain-link verification, key rotation/revocation rules, active-epoch matching and externally retained checkpoint digest matching. It rejects rollback, stale checkpoints, competing forks, revoked witness identities and modified bundle reports. Usage:

```bash
python3 research/sef2/evaluation_kit/verify_historical.py --input /tmp/aml-sef2-evaluation --trust-manifest /secure/trust-manifest.json --pinned-manifest-sha256 MANIFEST_DIGEST --history-db /secure/history.sqlite --approver-public-hex INDEPENDENT_APPROVER_PUBLIC_KEY --checkpoint /secure/checkpoint.json --pinned-checkpoint-sha256 EXTERNALLY_RETAINED_CHECKPOINT_DIGEST --active-epoch 1
```

All trusted inputs must come from **independent, controlled provisioning**, not the evidence bundle. The verifier rejects inconsistent history but does not create independent publication, guarantee global freshness, or prevent a privileged attacker from replacing both the history and its external pin. The legacy `verify_enrolled.py` still exists for compatibility and does not perform full-history verification. This is synthetic research, not production-ready authorization.

## Multi-witness checkpoint publication research

`checkpoint_council.py` provides signed checkpoint attestations by distinct Ed25519 witness identities, separately provisioned public keys, configurable quorum (minimum two), retained per-witness checkpoint heads, and fail-closed detection of signature forgery, duplicate or unknown witnesses, stale epochs, same-epoch forks and inconsistent approver identities. `WitnessCouncil.retain()` updates **in-memory** witness retention only after quorum consistency. Each actual witness must be separately administered and retain its state in independently controlled durable storage for the intended guarantees. The library does not provide a network publication service, authenticated cross-witness gossip, durable external retention, trust-root enrollment, global latest-epoch consensus or Byzantine fault tolerance. It is a synthetic adversarial research primitive; the strict historical bundle verifier does not yet require council attestations.

## Durable witness publication and strict enterprise quorum

`durable_checkpoint_witness.py` adds a per-witness SQLite store for monotonic epoch/head retention and signed publication receipts; the caller must provision a separate file, private key and administrative boundary for each witness. Same-epoch replay returns the original signed receipt without creating another publication; rollback and conflicting heads fail closed. `verify_quorum.py` requires both the complete signed-history enterprise verification and a quorum of Ed25519 attestations from independently pinned witness keys. It rejects missing, forged, duplicate and inconsistent witness attestations. This is an **offline authenticated publication protocol**: no HTTP/TLS service, witness deployment or independent operators are supplied. An administrator able to roll back a witness database and its keys can defeat that witness's local retention. The verifier does not query witness stores for latest heads or independently verify their durable state; signed attestations may be stale if the evaluator supplies an old but pinned checkpoint. External freshness, quorum intersection across epochs, audit gossip and compromise recovery remain open.

## Challenge-bound external witness freshness

`witness_freshness.py` introduces a transport-independent authenticated latest-checkpoint endpoint backed by each witness's own durable SQLite store. An evaluator issues a fresh random 256-bit challenge and verifies signed replies from distinct independently pinned Ed25519 witness identities. Quorum validation fails closed on nonce replay, forged signatures, insufficient witnesses, stale epochs and cross-witness checkpoint conflicts. Deploy each endpoint under a separately administered process/key/storage boundary to obtain operational independence; this repository does not deploy services or provide TLS, HTTP, independent administrators, or live network reachability. **Important:** `verify_fresh` is a separate opt-in verification step and is not yet invoked automatically by `verify_quorum.py`. The caller must bind its expected checkpoint to the historical enterprise verifier, require both successful decisions and never reuse a challenge. A compromised quorum can still equivocate, and independent external audit gossip is not yet implemented.

## Live challenge-bound witness gate (research)

`witness_http_service.py` runs one loopback-only HTTP process per witness, each configured with a separate SQLite store, Ed25519 private key and witness ID. `witness_live_verifier.py` combines strict signed-history enterprise verification, signed publication quorum and a newly generated 256-bit challenge to every configured witness endpoint. All endpoints must answer successfully and the responses must match the independently pinned expected checkpoint. The transport is intentionally restricted to loopback, **not TLS or remotely deployed independent administration**. The live verifier is an additional strict entrypoint; legacy verifiers remain available. A compromised witness process can still sign false responses; key custody and independent operations are outside the fixture. No production network endpoints are deployed.

## Separate-process witness integration

`test_witness_process.py` starts two real independent Python witness HTTP child processes with separate Ed25519 signing keys and SQLite stores, exercises challenge-bound quorum, process termination, stale epochs, replay and cross-process conflicting history. The client disables proxy forwarding and HTTP redirects and validates parsed loopback endpoint origin to avoid URL user-info bypass. Tests remain synthetic localhost research, not independent organizational hosting. Witness private keys are fixture files with restrictive permissions; they are not HSM-backed. The current verifier still requires the evaluator to independently provision trustworthy pins and checkpoint freshness expectations.

## Authenticated witness checkpoint publication

`authenticated_publication.py` signs checkpoints under a separate approver Ed25519 key and domain separator. `witness_http_service.py` exposes a loopback-only `POST /publish` when the administrator explicitly provisions `--approver-public-file`. Invalid or missing approver signatures fail closed (403); stale epochs and same-epoch forks are rejected (409); same-head replay is idempotent. `POST /latest` remains a separately signed challenge-bound witness read. Each witness must be administered independently; localhost-only services do not demonstrate separate trust domains. Do not treat local database rollback or a compromised approver key as solved.

## One-command live enterprise demonstration

Run `python3 research/sef2/evaluation_kit/live_enterprise_demo.py --output /tmp/aml-sef2-live-enterprise`. It generates a synthetic three-party evidence bundle, signs and persists enrollment history, creates externally checkable manifest/checkpoint digests, starts two **real child-process** witness services with distinct temporary keys/stores, sends signed HTTP checkpoint publications, then runs the complete live quorum enterprise verifier. Negative controls reject a forged witness attestation and a killed witness process. Machine-readable `live-demo-report.json` records the outcomes and explicitly states that external independence is unproven. The demo generates all trust roots itself: publishing its pins alongside its evidence is **not** independent trust establishment. Witness key custody, TLS, geographically independent operators, external freshness attestation, and production execution remain unproven.

## Independent subprocess adversarial evidence

Run `python3 research/sef2/test_witness_recovery_controls.py --output /tmp/aml-sef2-witness-adversarial-report.json`. The process-level scenario checks authenticated advance and signed rollback rejection, cross-witness fork rejection, process restart retaining the original SQLite checkpoint, substitution of a pinned witness key, and rejection after restart while a conflicting witness remains. The JSON report records individual checks and subprocess PIDs. This test does not claim external independent administration or resistance to privileged database rollback.

## Independently pinned snapshot anti-rollback check

`external_witness_anchor.py` exports the latest witness-signed checkpoint into a separate anchor file and computes a canonical SHA-256 pin. The evaluator MUST retain the anchor and its expected digest outside the witness database rollback domain and obtain the witness public key independently. `verify_anchor` checks the externally pinned signed checkpoint against the complete retained database state and rejects even an internally consistent restored earlier SQLite snapshot. Tests include database backup/restore, restart, modified anchors, wrong pins and wrong keys. **This is an independent verification gate, not automatic enforcement by the witness HTTP service**; operators must require it before trusting a restored witness. The anchor is not hardware monotonic storage, and an attacker controlling both the witness DB and the independent pin can defeat it.

## Enforced pinned witness startup (research)

Run the witness service with `--anchor-file`, `--anchor-pin`, and `--witness-public-file` together. Startup fails unless the independently pinned witness key and anchor match the complete local retained checkpoint. Every HTTP request revalidates the anchor and returns HTTP 503 on mismatch, preventing a restored earlier snapshot from serving a trusted freshness response. `verify_pinned_live` adds an external-anchor gate to the enterprise live verification API; callers must explicitly use this strict API and independently provision all anchor pins. Anchored service mode intentionally freezes checkpoint publication until a separately authorized anchor update; no atomic external-anchor update protocol is implemented. No protection against a compromised external anchor authority or a database rollback between verification and use is claimed.
