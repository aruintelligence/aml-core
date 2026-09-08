# Build an external AML verifier in 10 minutes

**SHIPPED reproduction path.**

You do not need to implement the AML language, compiler, browser bridge, policy engine, or UI firewall.

To challenge the public witness contract, implement one narrow black-box verifier.

## Minute 0–1 — pin the exact contract

Target this immutable snapshot:

```text
snapshot_id: aml-verifier-contract-2026-09-08-01
source_commit: b1ff5a87c7b19ae6338503a58ab6257a5b2add0b
```

Read:

- `protocol/verification-contract-v1.json`
- `protocol/VERIFIER_CONTRACT_VERSIONING.md`

Do not implement a loose label such as "latest AML verifier v1" if you want reproducible interoperability evidence.

## Minute 1–3 — read the contract

Read:

- `protocol/aml-verifier-cli.md`
- `protocol/sorted-json-v1.md`
- `protocol/aml-witness-bundle.schema.json`

Use the golden artifact:

- `independent/python/witness-vector.json`

## Minute 3–7 — implement five checks

At minimum:

1. canonicalize and verify the bundle SHA-256;
2. canonicalize and verify nested evidence + receipt SHA-256 values;
3. enforce verifier challenge freshness and binding;
4. recompute the public JWK fingerprint;
5. verify the P-256 ECDSA/SHA-256 session signature.

Do not import the AML reference verifier if the goal is independent reproduction.

## Minute 7–8 — expose the tiny CLI

```text
your-verifier --now 2030-01-01T00:05:00Z bundle.json
```

stdout:

```json
{"valid":true,"reason":"YOUR_SUCCESS_REASON"}
```

Exit `0` on valid; nonzero on invalid.

## Minute 8–9 — run the black-box harness

```bash
node scripts/run-verifier-conformance.mjs -- your-verifier
```

The harness checks:

- golden vector PASS;
- tampered purpose FAIL;
- tampered challenge FAIL;
- expired challenge FAIL.

## Minute 9–10 — publish a precise claim

Generate a machine-readable implementation claim:

```bash
node scripts/create-verifier-implementation-claim.mjs \
  --implementation-id your-verifier \
  --implementation-version 0.1.0 \
  --runtime your-runtime \
  --source-url https://github.com/you/your-verifier \
  --command './your-verifier --now 2030-01-01T00:05:00Z bundle.json' \
  --external true
```

Then publish:

- your source;
- implementation claim;
- runtime/version;
- exact black-box result JSON;
- at least one deliberate mutation result;
- any disagreement you found.

Submit it to GitHub Issue #17 or the external-verifier issue templates.

## If you fail

Publish the failure. A cross-runtime mismatch is valuable protocol evidence.

## Claim boundary

A snapshot identifies the exact contract target. An implementation claim says what you intended to implement. Passing the harness means your executable matched this project-defined compatibility target for the supplied cases. None of those objects means certification, official AML authorization, standards-body approval, institutional independence, or proof that the declared meaning/scores are objectively true.
