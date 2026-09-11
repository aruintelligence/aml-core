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

A valid quorum is evidence that the configured threshold of eligible keys signed replay-valid transcripts with the same transcript root. It is not proof that the signers are independent organizations, that their identities are verified, or that the underlying policy is correct.
