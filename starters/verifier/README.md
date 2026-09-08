# AML external verifier starter

**SHIPPED starter.**

Goal: make an outside verifier reproducible without importing AML reference-verifier code.

## Contract

Your program must accept:

```text
your-verifier --now 2030-01-01T00:05:00Z bundle.json
```

and print:

```json
{"valid":true,"reason":"YOUR_REASON"}
```

Exit `0` on valid and nonzero on invalid.

## Implement only these checks

1. `sorted-json-v1` canonicalization;
2. receipt SHA-256;
3. browser-evidence SHA-256;
4. witness-bundle SHA-256;
5. challenge freshness/binding;
6. session public-key fingerprint;
7. P-256 ECDSA/SHA-256 signature verification.

## Test it

From a clone of `aml-core`:

```bash
node scripts/run-verifier-conformance.mjs -- your-verifier
```

Expected cases:

- golden-valid -> PASS
- tampered-purpose -> FAIL
- tampered-challenge -> FAIL
- expired-challenge -> FAIL

## Publish evidence

Copy `verifier-manifest.template.json`, replace placeholders, publish your source and conformance output, then submit an **External verifier report** issue.

Negative results and disagreements are welcome.

## Important

Do not call your implementation officially certified by ĀRU merely because it passes these project-defined tests. Technical compatibility and official branding are separate.
