# Build an external AML verifier in 10 minutes

**SHIPPED reproduction path.**

You do not need to implement the AML language, compiler, browser bridge, policy engine, or UI firewall.

To challenge the public witness contract, implement one narrow black-box verifier.

## Minute 0–2 — read the contract

Read:

- `protocol/aml-verifier-cli.md`
- `protocol/sorted-json-v1.md`
- `protocol/aml-witness-bundle.schema.json`

Use the golden artifact:

- `independent/python/witness-vector.json`

## Minute 2–7 — implement five checks

At minimum:

1. canonicalize and verify the bundle SHA-256;
2. canonicalize and verify nested evidence + receipt SHA-256 values;
3. enforce verifier challenge freshness and binding;
4. recompute the public JWK fingerprint;
5. verify the P-256 ECDSA/SHA-256 session signature.

Do not import the AML reference verifier if the goal is independent reproduction.

## Minute 7–9 — expose the tiny CLI

```text
your-verifier --now 2030-01-01T00:05:00Z bundle.json
```

stdout:

```json
{"valid":true,"reason":"YOUR_SUCCESS_REASON"}
```

Exit `0` on valid; nonzero on invalid.

## Minute 9–10 — run the black-box harness

```bash
node scripts/run-verifier-conformance.mjs -- your-verifier
```

The harness checks:

- golden vector PASS;
- tampered purpose FAIL;
- tampered challenge FAIL;
- expired challenge FAIL.

Then publish:

- your source;
- runtime/version;
- exact result JSON;
- at least one deliberate mutation result;
- any disagreement you found.

Submit it to GitHub Issue #17.

## If you fail

Publish the failure. A cross-runtime mismatch is valuable protocol evidence.

## Claim boundary

Passing the harness means your implementation matched this project-defined compatibility target for the supplied cases. It does not mean certification, official AML authorization, standards-body approval, or proof that the declared meaning/scores are objectively true.
