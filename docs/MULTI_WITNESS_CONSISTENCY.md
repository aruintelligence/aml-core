# Multi-witness consistency

AML's witness layer can require a verifier-selected quorum of distinct trusted witness identities to agree on the same checkpoint root and sequence. Duplicate witness identities, duplicate public-key fingerprints, untrusted witnesses, revoked witnesses, split-view roots, split-view sequences, and checkpoint rollback below the verifier's minimum accepted sequence do not satisfy quorum.

`multi-witness-consistency-contract.json` defines the policy. `conformance/multi-witness/vectors.json` carries executable accept/reject cases. `scripts/check-multi-witness-consistency.mjs` generates ephemeral CI-only Ed25519 witnesses, verifies signatures, applies verifier-supplied trust, and proves that two agreeing trusted witnesses satisfy the current project-controlled quorum while split views and quorum inflation fail.

The generated report deliberately states `synthetic_witnesses_only: true` and `external_independent_witnesses_claimed: false`. Passing this project workflow is not evidence that independent organizations have witnessed AML releases. External witness evidence must come from independently controlled identities and published receipts that can be verified separately.
