# Verify AML without trusting AML

**SHIPPED verification entry point.**

The fastest way to challenge the public AML witness contract is to verify the same artifact in your own runtime.

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

All are maintained inside this repository and **do not count as independent external witnesses**.

## External evidence

Current machine-readable external witness registry:

[`WITNESSES.json`](WITNESSES.json)

The registry intentionally remains empty until reproducible evidence maintained outside `aruintelligence/aml-core` exists.

Submit a result through GitHub Issue #17 or the **External verifier report** issue template.

## Claim boundary

A successful reproduction is project-defined interoperability evidence. It is not certification, standards-body approval, official trademark authorization, or proof that the underlying declared intent/scores are objectively true.
