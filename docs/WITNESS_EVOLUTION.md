# Witness evolution and portable consistency proofs

AML's release-trust control plane now defines project-controlled semantics for carrying trust forward between checkpoint heads and witness sets.

A consistency proof binds a known checkpoint root and sequence to its exact successor. A verifier rejects skipped sequences, rollback, and a successor that does not name the verifier's accepted predecessor root.

Witness-set rotation is versioned and must bind the previous set root. Rotation may overlap old and new witnesses, but it may not collapse below the configured minimum quorum, duplicate witness identities or keys, or reintroduce revoked witnesses.

External witness submissions use Ed25519 receipts that bind a checkpoint root and sequence. Signature validity does not imply trust, and an embedded public key is never implicitly trusted. Independence is also not self-attested: only the verifier may classify a trusted signer as independent based on evidence outside this repository.

CI uses ephemeral synthetic witnesses only. Passing CI proves the project-controlled mechanics. It does not establish an external witness network, public timestamp authority, third-party attestation, standards approval, or independent adoption evidence.
