# AML Verification Contract Snapshot

**SHIPPED prototype interoperability mechanism.**

A version label such as `v1` is too weak when independent runtimes must agree on exact bytes, schemas, vectors, and behavior.

AML therefore publishes `aml-verification-contract-snapshot/1`.

Current snapshot:

```text
snapshot_id: aml-verifier-contract-2026-09-08-01
source_commit: b1ff5a87c7b19ae6338503a58ab6257a5b2add0b
canonicalization: sorted-json-v1
witness_schema: aml-witness-bundle/1
```

The immutable Git commit anchors the exact historical contents of every path listed in `protocol/verification-contract-v1.json`.

An independent implementation can therefore say:

> I implement AML verifier contract snapshot `aml-verifier-contract-2026-09-08-01`, anchored at commit `b1ff5a87c7b19ae6338503a58ab6257a5b2add0b`.

That statement is much more precise than merely saying "supports AML v1."

## Why this exists

Without a snapshot, two runtimes can claim the same protocol name while using different:

- canonical JSON rules;
- witness schemas;
- challenge semantics;
- golden vectors;
- CLI expectations;
- mutation tests.

The snapshot creates an immutable comparison point.

## What it does not prove

A snapshot does not prove an implementation is correct, independent, secure, endorsed, certified, or standards-body approved. It identifies the exact contract the implementation claims to target.

## Verify the snapshot structure

```bash
node scripts/check-verification-contract-snapshot.mjs
```

## Create an implementation claim

```bash
node scripts/create-verifier-implementation-claim.mjs \
  --implementation-id example-verifier \
  --implementation-version 0.1.0 \
  --runtime rust-1.90 \
  --source-url https://github.com/example/aml-verifier \
  --command './aml-verifier --now 2030-01-01T00:05:00Z bundle.json' \
  --external true
```

Then run the black-box conformance harness against the actual executable.

A claim is not conformance evidence until the executable behavior is reproduced.
