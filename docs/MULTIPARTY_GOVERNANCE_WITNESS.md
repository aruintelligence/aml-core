# Multi-party governance witnessing

ĀML can now evaluate a quorum of independently signed governance transcripts without collapsing cryptographic validity into trust.

The contract is `aml-governance-witness-quorum/1`.

A quorum policy may require:

- a minimum threshold of eligible witnesses;
- distinct signing keys;
- an explicit trusted-fingerprint set;
- a required signer scope;
- exclusion of revoked key fingerprints.

Eligible witnesses must present a replay-valid governance transcript, a valid Ed25519 signature, and satisfy the supplied trust policy. Witnesses are grouped by transcript root. A quorum is met only when enough eligible distinct witnesses attest to the same transcript root.

This is intentionally not a distributed-consensus protocol. It does not solve network membership, Byzantine consensus, timestamp authority, identity proofing, or production key distribution. It provides a deterministic threshold-attestation primitive that external systems can compose with stronger trust infrastructure.

CLI:

```bash
aml-governance-witness-quorum quorum-input.json
```

Programmatic API:

```js
import { evaluateGovernanceWitnessQuorum } from "aml-core";

const result = evaluateGovernanceWitnessQuorum(signedTranscripts, {
  threshold: 2,
  trusted_fingerprints,
  revoked_fingerprints,
  required_scope: "governance-witness"
});
```

Quorum configuration safety: `aml-governance-witness-quorum` authorizes only when the pinned policy's `threshold` (k) and declared `trusted_fingerprints` (n) satisfy `2k - n - 1 >= 1`, so two conflicting transcript roots cannot both reach quorum while one witness is faulty. For example 3-of-4, 4-of-5 and 5-of-7 pass; 1-of-1, 2-of-3, 2-of-4 and 4-of-7 are refused with `AML_AUTHZ_QUORUM_CONFIG_UNSAFE`. The evaluation result reports `quorum_safety` (including `liveness_fault_tolerance = n - k`, which this rule does not enforce: n-of-n passes but halts if any witness is unavailable). An explicit threshold that is not a positive integer is a policy error (`policy_errors: ["invalid_threshold"]`), never silently replaced by 1. The same rule is implemented in `protocol/quorumSafety.js`, `independent/python/quorum_safety.py` and `independent/go/quorumsafety.go` with shared vectors in `conformance/quorum-safety/`.

A valid quorum is evidence that the configured threshold of eligible keys signed replay-valid transcripts with the same transcript root. It is not proof that the signers are independent organizations, that their identities are verified, or that the underlying policy is correct.
