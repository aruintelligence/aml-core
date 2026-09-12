# Signed transparency checkpoints and witness receipts

AML's project-controlled release transparency layer now separates four questions that are easy to conflate: whether a checkpoint is internally well formed, whether its Ed25519 signature is mathematically valid, whether the signer is trusted by the verifier, and whether the checkpoint correctly succeeds the verifier's previously accepted head.

`checkpoint-signing-contract.json` defines those boundaries. A valid embedded public key is not automatically trusted. A verifier must supply trust, and revoked or retired signers are rejected. Checkpoint succession is monotonic: after genesis, a successor must advance exactly one sequence number and name the verifier's previously accepted checkpoint root. A checkpoint that points at another predecessor is treated as a fork for that verifier, and a checkpoint below the verifier's minimum accepted sequence is rejected as rollback.

The CI gate uses ephemeral Ed25519 keys generated during the job. They are test fixtures only. No production private signing material is stored, generated for official use, or implied by this workflow.

The witness-receipt protocol binds a witness identifier, checkpoint sequence, and checkpoint root. Receipt signature validity is deliberately separate from witness trust. The CI receipt is labeled `synthetic_ci_reproduction`; it proves the project verifier logic can exercise this boundary, not that an independent third party witnessed AML.

This layer does not create an external transparency service, public timestamp authority, independent witness network, production ARU signature, or third-party certification. Those would require genuinely external infrastructure or actors and separately verifiable evidence.
