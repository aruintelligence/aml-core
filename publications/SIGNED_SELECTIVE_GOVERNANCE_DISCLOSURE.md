# Selective AI-governance evidence can now carry an authenticated commitment

Selective disclosure solves only part of the evidence problem. A Merkle proof can show that a disclosed entry belongs to a commitment, but the commitment itself still needs an authenticated origin.

ĀML now adds a project-defined Ed25519 signature layer for governance-disclosure commitments.

The signed material is deliberately compact: source transcript root, source entry count, and disclosure Merkle root. A verifier can then validate a selective disclosure against that signed commitment while separately applying its own trusted-key, revoked-key, and signer-scope policy.

Protocols:

```text
aml-governance-disclosure-commitment/1
aml-signed-governance-disclosure-commitment/1
```

This produces a chain like:

```text
full governance transcript
→ Merkle commitment
→ selected disclosed entries + inclusion proofs
→ signed commitment
→ verifier-controlled trust / revocation / scope decision
```

The separation matters. Signature validity is not the same as signer trust, and signer trust is not the same as official ĀRU authorization or independent validation.

This is also not zero-knowledge proof. The selective-disclosure metadata remains visible. The shipped milestone is narrower: a verifier can authenticate the compact commitment that anchors a partial disclosure without requiring publication of the full transcript.
