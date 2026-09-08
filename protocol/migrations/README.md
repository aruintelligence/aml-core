# AML verifier contract migrations

**Status: SHIPPED evolution rulebook.**

Verifier contract snapshots are immutable historical targets. A future snapshot does not rewrite an older snapshot's meaning.

## Required migration edge

Every snapshot after the first must publish one `aml-verification-contract-migration/1` object from its declared predecessor.

That object must state:

- source snapshot;
- destination snapshot;
- compatibility classification;
- every changed locked path;
- behavior changes;
- whether old artifacts remain verifiable under their original snapshot.

## Compatibility classes

### backward-compatible

Existing artifacts remain verifiable under the old snapshot and the new snapshot accepts the old behavior without additional conditions.

### conditionally-compatible

Existing artifacts remain historically verifiable, but use under the new snapshot requires an explicit condition, adapter, profile, or migration step.

### breaking

The new snapshot intentionally changes one or more verifier-contract behaviors. Old artifacts still retain their historical meaning under the old snapshot; the new snapshot must not silently reinterpret them.

## Non-negotiable historical rule

```text
old artifact + old snapshot -> historical meaning preserved
```

A later implementation may support old snapshots, reject them as unsupported, or require an adapter. It may not claim that the old snapshot meant something different.

## Current state

There is currently one published verifier contract snapshot and therefore **zero migration edges**.

Do not create a ceremonial Snapshot 2 with identical locked behavior. Publish a new snapshot only when a real contract change needs a new interoperability target.
