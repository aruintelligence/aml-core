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
