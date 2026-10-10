# Repairable ĀML cold storage

`aml-evidence-shard/1` splits a verified migration handoff into three independent files: data share 0, data share 1, and an XOR parity share. **Any two distinct shares** reconstruct the exact canonical handoff bytes. Each file carries its own SHA-512 segment digest and SHA3-512 envelope root; the reconstructed handoff is checked again under an external trust policy before it is returned.

```bash
node scripts/evidence-shards.mjs create handoff.json trusted-policy.json new-share-directory
node scripts/evidence-shards.mjs recover new-share-directory/share-0.json new-share-directory/share-2.json trusted-policy.json recovered-handoff.json
node scripts/evidence-shards.mjs repair new-share-directory/share-0.json new-share-directory/share-2.json trusted-policy.json replacement-share-1.json
node scripts/evidence-repair-record.mjs create new-share-directory/share-0.json new-share-directory/share-2.json replacement-share-1.json trusted-policy.json new-repair-record.json
node scripts/evidence-repair-record.mjs verify new-repair-record.json new-share-directory/share-0.json new-share-directory/share-2.json replacement-share-1.json trusted-policy.json
node scripts/evidence-migration.mjs recover recovered-handoff.json trusted-policy.json recovered-v1.json
python3 independent/python/recover_evidence_shards.py new-share-directory/share-0.json new-share-directory/share-2.json trusted-policy.json recovered-handoff-python.json
python3 independent/python/repair_evidence_share.py new-share-directory/share-0.json new-share-directory/share-2.json trusted-policy.json replacement-share-1-python.json
python3 independent/python/evidence_repair_record.py verify new-repair-record.json new-share-directory/share-0.json new-share-directory/share-2.json replacement-share-1.json trusted-policy.json
```

The create command refuses an existing directory. Recovery accepts two or three share paths and writes only to a new destination. It tries all valid distinct pairs when three are supplied, so one damaged file can be ignored. If no pair reconstructs a handoff that verifies under the caller's trust policy, recovery fails. Preserve the original v1 archive, the handoff, and external trust material as well as the shares.

Repair accepts exactly two valid, distinct surviving shares and an external policy with an accepted head. It independently verifies the recovered handoff, checks that both survivors exactly match the regenerated canonical set, and rehearses all three pairs before writing the missing share to a new path. It refuses to overwrite a file. The Python implementation independently recreates the exact share bytes. Replace a damaged carrier only after inspecting the new file and report; keep the policy outside the share set. This is local verification, not a claim that the physical copy reached another location.

Create a [repair record](../independent/vectors/repair-record-v1/README.md) after rebuilding a share. It deterministically binds both survivor roots, the replacement root, recovered payload, accepted head, and policy digest. Verification reruns the repair from the original files; it does not rely on the record's self-contained hashes. Store the record alongside operational notes, while keeping independent policy custody and any human approval trail outside these files. The record has no date, signature, custody proof, or claim that an offsite copy was placed.

The [fixed share wire vector](../independent/vectors/shards-v1/README.md) is recovered independently by Python. CI checks all three pairs, a damaged file, rehashed corruption, rollback, overwrite refusal, signed receipts, missing receipt trust, and revocation. The independent Python reader verifies the full versioned handoff and its original archive after reconstruction.

Run the [three-pair recovery drill](EVIDENCE_DRILL.md) against the copies actually stored in separate locations. Its readiness report flags a damaged set while recovery from the remaining two is still possible.

This is **redundancy, not secret sharing**. A single share reveals part of the handoff; two shares reveal all of it. Encrypt separately when confidentiality is needed. Self-contained hashes detect corruption but anyone can recompute them. Receipt signers, witness keys, revocations, and a previously accepted head must come from outside the share set. Two files on one failing device do not provide useful physical resilience, so place copies in distinct failure domains and rehearse recovery. This prototype does not establish historical truth, independent witnesses, storage durability, or a 5,000-year cryptographic guarantee.
