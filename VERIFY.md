# Verify AML without trusting AML

**SHIPPED verification entry point.**

The fastest way to challenge the public AML witness contract is to verify the same artifact in your own runtime.

## Immutable contract target

Do not implement a vague label such as "AML verifier v1." Target the exact published snapshot:

```text
snapshot_id: aml-verifier-contract-2026-09-08-01
source_commit: b1ff5a87c7b19ae6338503a58ab6257a5b2add0b
```

Snapshot: [`protocol/verification-contract-v1.json`](protocol/verification-contract-v1.json)

The source commit is the immutable historical anchor for the exact locked path set.

## One command

Implement the tiny CLI contract in [`protocol/aml-verifier-cli.md`](protocol/aml-verifier-cli.md), then run:

```bash
node scripts/run-verifier-conformance.mjs -- your-verifier
```

The harness requires:

```text
golden witness       -> PASS
tampered receipt     -> FAIL
tampered challenge   -> FAIL
expired challenge    -> FAIL
```

## Canonical artifact

[`independent/python/witness-vector.json`](independent/python/witness-vector.json)

## Public contracts

- [`protocol/verification-contract-v1.json`](protocol/verification-contract-v1.json)
- [`protocol/aml-verification-contract-snapshot.schema.json`](protocol/aml-verification-contract-snapshot.schema.json)
- [`protocol/aml-verifier-implementation-claim.schema.json`](protocol/aml-verifier-implementation-claim.schema.json)
- [`protocol/aml-witness-bundle.schema.json`](protocol/aml-witness-bundle.schema.json)
- [`protocol/aml-browser-evidence.schema.json`](protocol/aml-browser-evidence.schema.json)
- [`protocol/aml-verification-challenge.schema.json`](protocol/aml-verification-challenge.schema.json)
- [`protocol/aml-session-attestation.schema.json`](protocol/aml-session-attestation.schema.json)
- [`protocol/sorted-json-v1.md`](protocol/sorted-json-v1.md)
- [`protocol/aml-verifier-cli.md`](protocol/aml-verifier-cli.md)

## Reference implementations

- Browser / JavaScript
- Python standard library
- Go standard library
- HTTP reference service

Each reference implementation now publishes an `aml-verifier-implementation-claim/1` bound to the same immutable contract snapshot.

All are maintained inside this repository and **do not count as independent external witnesses**.

## Claim your implementation precisely

Generate a machine-readable claim:

```bash
node scripts/create-verifier-implementation-claim.mjs \
  --implementation-id my-verifier \
  --implementation-version 0.1.0 \
  --runtime rust-1.90 \
  --source-url https://github.com/example/my-verifier \
  --command './my-verifier --now 2030-01-01T00:05:00Z bundle.json' \
  --external true
```

A claim says what you target. It does not prove conformance.

## External evidence

Current machine-readable external witness registry:

[`WITNESSES.json`](WITNESSES.json)

The registry intentionally remains empty until reproducible evidence maintained outside `aruintelligence/aml-core` exists.

Submit a result through GitHub Issue #17, the **External verifier report** template, or the **External verifier implementation claim** template.

## Claim boundary

A successful reproduction is project-defined interoperability evidence. An implementation claim is a compatibility declaration. Neither is certification, standards-body approval, official trademark authorization, proof of institutional independence, or proof that the underlying declared intent/scores are objectively true.
