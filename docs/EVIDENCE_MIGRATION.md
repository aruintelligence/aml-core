# Versioned ĀML archive handoff

`aml-evidence-migration/1` is an explicit, lossless handoff from the canonical v1 archive into a v2 layout. It keeps the **complete canonical v1 archive bytes** in `source_archive_base64` and repeats its capsule, renewal, and policy-hint components. The verifier compares the repeated component bytes exactly with those inside v1, checks SHA3-512 and SHA-512 digests and both handoff roots, and verifies v1 under trust supplied outside the handoff.

```bash
node scripts/evidence-migration.mjs create archive-v1.json trusted-policy.json > handoff.json
node scripts/evidence-migration.mjs verify handoff.json trusted-policy.json
node scripts/evidence-migration.mjs recover handoff.json trusted-policy.json recovered-v1.json
```

`recover` verifies first, then writes canonical v1 archive bytes with a final newline to a **new** file. It refuses to overwrite a destination. The recovery drill using the frozen archive v1 vector produces a file that compares byte-for-byte with that vector.

For signed v1.1 receipts, the external policy must contain `trusted_receipt_fingerprints` in addition to the renewal witness `trusted_fingerprints`. `revoked_receipt_fingerprints` can withdraw receipt trust. Legacy v1.0 receipt signatures are not accepted for this handoff because their signer and signed time were not bound. The embedded policy hint is never used as authority. An `accepted_head` obtained and remembered separately is needed to bound rollback.

This handoff makes the format transition inspectable. It is **not** a security upgrade to a future cryptographic system. Its new SHA-512 digest provides a second current hash check, while the original SHA3-512 archive, Ed25519 signatures, public keys, trust policy, and original bytes remain necessary. Do not discard v1. A future algorithm change needs a new protocol, independent implementation, fresh trust decisions, and a reviewed migration; it must not silently reinterpret this v1 handoff.
