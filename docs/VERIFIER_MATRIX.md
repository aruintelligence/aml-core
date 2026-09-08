# AML verifier implementation matrix

**SHIPPED reference matrix.**

The same `aml-witness-bundle/1` contract is currently exercised through multiple reference paths.

| Verifier path | Runtime | Imports another AML verifier? | Counts as external witness? | Public contract |
| --- | --- | --- | --- | --- |
| Browser / detached | JavaScript + WebCrypto | No | No | `aml-witness-bundle/1` |
| Web Worker | JavaScript + WebCrypto | No | No | `aml-witness-bundle/1` |
| HTTP service | Node.js | Reference implementation | No | `/v1/verify-witness-bundle` |
| Python | Python standard library | No | No | `protocol/aml-verifier-cli.md` |
| Go | Go standard library | No | No | `protocol/aml-verifier-cli.md` |

All rows above are maintained inside `aruintelligence/aml-core`. They are implementation diversity, not independent adoption.

## Required black-box cases

The public harness requires:

1. golden witness -> PASS;
2. bound receipt mutation -> FAIL;
3. bound challenge mutation -> FAIL;
4. expired challenge -> FAIL.

Run:

```bash
node scripts/run-verifier-conformance.mjs -- <verifier-command>
```

## The next empty row

The important next row is one maintained outside this repository.

Submit it through the **External verifier report** issue template or Issue #17.

Disagreement is not failure of the witness process. If an outside runtime rejects a bundle our reference runtimes accept—or accepts one we reject—that mismatch should be published and reduced to a protocol vector.

## Claim boundary

This matrix shows project-maintained implementation paths. It does not prove institutional independence, certification, correctness of declared inputs, or standards-body recognition.
