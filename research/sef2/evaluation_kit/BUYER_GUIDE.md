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
