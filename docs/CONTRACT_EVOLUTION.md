# AML contract evolution

**Status: SHIPPED prototype governance surface.**

AML verifier contracts are designed to evolve without rewriting history.

## The rule

```text
Snapshot N is immutable.
Snapshot N+1 must declare what changed.
Old artifacts keep their Snapshot N meaning.
```

A new snapshot is warranted only when a locked verifier-contract behavior changes in a way implementers need to target explicitly.

## Migration object

Every later snapshot must publish an `aml-verification-contract-migration/1` object containing:

1. predecessor snapshot;
2. successor snapshot;
3. compatibility classification;
4. changed locked paths;
5. behavior changes;
6. historical-artifact policy.

## Why this matters

Without explicit migration, two implementations can both say "AML verifier v1" while hashing different bytes or enforcing different challenge rules.

Snapshot IDs remove that ambiguity.

Migration objects make evolution inspectable.

Historical verification prevents future AML versions from changing what old evidence meant.

## Compatibility is not morality

A migration classification says whether verifier behaviors remain interoperable. It does not certify the policies, declared purpose, attention values, restoration values, institution, or software as correct or trustworthy.

## Current lineage

Current snapshot:

`aml-verifier-contract-2026-09-08-01`

Current migration count:

`0`

That zero is intentional. AML will not invent a Snapshot 2 until a real locked-contract change exists.
