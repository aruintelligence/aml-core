# Cold archive for ĀML decisions

The archive is one JSON file containing exact canonical UTF-8 bytes for an evidence capsule, its renewal records, and a policy snapshot, encoded as base64. A SHA3-512 manifest binds the three components and an archive root binds the manifest, readable summary, and recovery note. Decoding does not require the original UI or a network connection.

The policy snapshot is a **hint about what someone claimed at archive time**. It is not an authority. Verification always requires trusted public-key fingerprints and any previously accepted head supplied from outside the archive. The CLI never imports trust from `policy-hint.json` on extraction.

```bash
node scripts/evidence-archive.mjs create capsule.json renewals.json policy.json > archive.json
node scripts/evidence-archive.mjs verify archive.json trusted-policy.json
node scripts/evidence-archive.mjs extract archive.json trusted-policy.json recovered-archive
```

`create` requires a valid capsule and a valid renewal chain under the supplied policy. `verify` returns a nonzero exit code if the archive root, component hashes, canonical bytes, capsule bindings, renewal succession, signatures, quorum, or external trust policy fails. `extract` verifies first, then creates a **new** directory with `capsule.json`, `renewals.json`, `policy-hint.json`, and `README.txt`; it will not overwrite an existing directory.

An independent Python verification path checks unsigned capsules, signed v1.1 capsules, and Ed25519 renewal witnesses without importing ĀML's JavaScript implementation. Install Python 3.12+ and `cryptography>=42,<51`, then run:

```bash
python3 independent/python/verify_evidence_archive.py archive.json trusted-policy.json
```

Its trust file must come from a separate, authenticated source. For a signed capsule, add `trusted_receipt_fingerprints` to that file, separately from the renewal `trusted_fingerprints`; optional `revoked_receipt_fingerprints` can withdraw receipt trust. The verifier rejects duplicate JSON keys, noncanonical component bytes, untrusted or revoked receipt signers or renewal witnesses, broken succession, and rollback against a separately remembered accepted head. It rejects legacy v1.0 receipt signatures because they do not bind signer and signed time. CI generates artifacts in JavaScript and checks success and mutation cases in Python.

The [fixed archive v1 wire vector](../independent/vectors/archive-v1/README.md) records byte-for-byte archive and policy files plus expected digests. CI checks that the producer still emits those exact bytes and that the independent Python verifier accepts the frozen archive. Its published keys are synthetic test data and must never be used as real witnesses.

The [versioned migration handoff](EVIDENCE_MIGRATION.md) retains the complete canonical v1 archive while repacking the components into a v2 layout. It verifies exact component equivalence and can recover the original canonical archive bytes. This demonstrates an explicit format transition, not an upgrade in cryptographic strength.

Use the [renewal API](EVIDENCE_RENEWAL.md) to construct the `renewals.json` array. The archive file remains inspectable as plain JSON, while its base64 fields preserve exactly one canonical byte representation of each component. The `summary` is derived and checked again; a changed summary is rejected. Rehashing the unkeyed archive root cannot forge signatures from verifier-trusted keys.

The archive is a prototype preservation format, not a substitute for redundant storage, key custody, trustworthy timestamping, independent witnessing, source and policy preservation, or periodic migration. SHA3-512 and Ed25519 are current algorithms; future replacement requires a new protocol and an independently reviewable migration. Repository tests use synthetic keys and project-authored evidence.
