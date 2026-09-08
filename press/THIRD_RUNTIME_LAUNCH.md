# SHIPPED — AML now verifies the same witness contract in JavaScript, Python, and Go

The interesting part is not that three languages exist.

The interesting part is that they are all aimed at the **same public artifact contract** instead of sharing one verifier implementation.

ĀML now publishes:

- `aml-witness-bundle/1`
- `sorted-json-v1`
- a golden witness vector
- a tiny verifier CLI contract
- a black-box conformance harness
- dependency-free Python verification
- standard-library Go verification

Run your own verifier against the same target:

```bash
node scripts/run-verifier-conformance.mjs -- your-verifier
```

The harness demands:

- original bundle: PASS
- tampered receipt: FAIL
- tampered challenge: FAIL
- expired challenge: FAIL

If your runtime disagrees, publish the disagreement.

That is more valuable than pretending every implementation agrees.

Repository:
https://github.com/aruintelligence/aml-core

10-minute external verifier path:
https://github.com/aruintelligence/aml-core/blob/main/docs/EXTERNAL_VERIFIER_10_MINUTES.md

**Status: SHIPPED prototype.** JavaScript, Python, and Go paths in this repository are all maintained by the AML project and do not count as independent external witnesses.
