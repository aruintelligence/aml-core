# Verifier contract migration checklist

**Status: SHIPPED maintainer checklist.**

Use this only when a locked verifier-contract behavior genuinely changes.

## Before creating a new snapshot

- [ ] Identify the exact locked path or behavior that changed.
- [ ] Explain why the existing snapshot cannot accurately describe the new behavior.
- [ ] Keep every historical snapshot file and source commit intact.
- [ ] Run the existing snapshot drift guard before changing anything.

## Create the new snapshot

- [ ] Assign a new immutable snapshot ID.
- [ ] Pin the exact source commit.
- [ ] List the complete locked path set.
- [ ] Publish or update golden vectors when bytes/behavior change.
- [ ] Do not reuse an old snapshot ID.

## Publish migration evidence

- [ ] Create one `aml-verification-contract-migration/1` object from the predecessor.
- [ ] List every changed locked path.
- [ ] Classify the migration: backward-compatible, conditionally-compatible, or breaking.
- [ ] Describe behavior before and after.
- [ ] State conditions/adapters when compatibility is conditional.
- [ ] Preserve `old_snapshot_verification_required: true`.
- [ ] Preserve `new_snapshot_may_reinterpret_old_artifacts: false`.

## Prove both timelines

- [ ] Old golden artifacts still verify under the old snapshot implementation.
- [ ] New golden artifacts verify under the new snapshot implementation.
- [ ] The migration planner reports the expected locked-path changes.
- [ ] Catalog and lineage checks pass.
- [ ] Independent verifier challenge is updated to name the exact snapshot.

## Claim boundary

A migration classification is interoperability metadata. It is not a standards-body ruling, trademark authorization, regulatory certification, or proof that declared interface meaning is objectively true.
