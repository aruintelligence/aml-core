# ĀML archive v1 wire vector

These fixed files let another implementation check the archive contract without running the current JavaScript producer. `archive.json` contains an unsigned evidence capsule and two SHA3-512 renewal records. The two Ed25519 witnesses on record 1 change to a partially rotated pair on record 2. `trusted-policy.json` is a separate verifier input with a two-key quorum and an accepted head at sequence 2. `expected.json` records independently checkable digests and the expected result.

The Ed25519 seeds are deliberately public test data (`0x11`, `0x22`, and `0x33`, repeated 32 times). **Never trust these keys for real evidence.** The timestamps and witnesses are synthetic; they prove neither the historical time nor independent attestation. The embedded archive policy hint is never an authority.

```bash
node scripts/check-evidence-archive-vector.mjs
python3 independent/python/verify_evidence_archive.py \
  independent/vectors/archive-v1/archive.json \
  independent/vectors/archive-v1/trusted-policy.json
```

To regenerate intentionally after a reviewed protocol or implementation change, run `node scripts/check-evidence-archive-vector.mjs --write` and review the byte diff and digest changes. The normal command fails on any drift. `archive_file_sha256` covers the complete UTF-8 `archive.json` file including its final newline. The archive root covers the canonical archive payload without its `root_sha3_512` field. Future formats should add a new vector directory instead of rewriting the v1 contract silently.
