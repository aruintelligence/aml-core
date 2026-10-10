# Repairable ĀML cold storage

`aml-evidence-shard/1` splits a verified migration handoff into three independent files: data share 0, data share 1, and an XOR parity share. **Any two distinct shares** reconstruct the exact canonical handoff bytes. Each file carries its own SHA-512 segment digest and SHA3-512 envelope root; the reconstructed handoff is checked again under an external trust policy before it is returned.

```bash
node scripts/evidence-shards.mjs create handoff.json trusted-policy.json new-share-directory
node scripts/evidence-shards.mjs recover new-share-directory/share-0.json new-share-directory/share-2.json trusted-policy.json recovered-handoff.json
node scripts/evidence-migration.mjs recover recovered-handoff.json trusted-policy.json recovered-v1.json
```

The create command refuses an existing directory. Recovery accepts two or three share paths and writes only to a new destination. It tries all valid distinct pairs when three are supplied, so one damaged file can be ignored. If no pair reconstructs a handoff that verifies under the caller's trust policy, recovery fails. Preserve the original v1 archive, the handoff, and external trust material as well as the shares.

This is **redundancy, not secret sharing**. A single share reveals part of the handoff; two shares reveal all of it. Encrypt separately when confidentiality is needed. Self-contained hashes detect corruption but anyone can recompute them. Receipt signers, witness keys, revocations, and a previously accepted head must come from outside the share set. Two files on one failing device do not provide useful physical resilience, so place copies in distinct failure domains and rehearse recovery. This prototype does not establish historical truth, independent witnesses, storage durability, or a 5,000-year cryptographic guarantee.
