# Release integrity monitoring and compromise response

AML's release-control plane distinguishes publication rehearsal, live registry observation, and incident response.

`release-integrity-contract.json` defines the stable-channel fields that are monitored. `immutable-release-manifest-contract.json` defines the immutable evidence bound to one stable release identity. `compromise-response-contract.json` defines the project-controlled response semantics for drift, signer compromise, source-tag drift, and manifest tampering.

The immutable manifest binds the stable package/version/dist-tag, source tag and resolved commit, release sequence, release-signing threshold, release-readiness digest, release-provenance root, packed artifact SHA-256, npm integrity, npm shasum, and publication transaction root. Its own root is recomputed by the verifier; mutating any bound field invalidates the manifest.

The `AML Release Integrity Monitor` workflow runs a deterministic rehearsal on pull requests and main. On scheduled or manual runs, it also checks the live npm registry. If the stable target is not yet published, the live monitor reports `inactive_unpublished`; that state is explicitly not represented as a passing registry-integrity result. Once the target is observable, the monitor verifies registry version, dist-tag, integrity, shasum, clean installation, API import, and installed CLI execution.

The compromise-response contract requires containment and verification for every modeled trigger. Artifact-integrity, source-tag, key-compromise, and manifest-tamper cases add revocation or repair steps as appropriate. Revoked signers do not satisfy release quorum; replacement keys require explicit trust configuration; recovery requires a fresh integrity receipt and a release sequence that is not older than the verifier's last accepted sequence.

These controls are project-generated release safety mechanisms. They do not independently revoke external credentials, guarantee containment, prove npm publication, create third-party certification, or replace an organization's incident-response process.
