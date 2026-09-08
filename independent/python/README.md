# Dependency-Free Python Witness Verifier

**Status: SHIPPED reference interoperability implementation**

This directory implements `aml-witness-bundle/1` from the public contracts without importing the AML JavaScript runtime.

It uses only the Python standard library, including a compact P-256 ECDSA verifier implemented directly from the published public JWK coordinates.

## Verify the golden vector

```bash
python3 independent/python/verify_witness.py \
  independent/python/witness-vector.json \
  --now 2030-01-01T00:05:00Z
```

Expected:

```json
{
  "valid": true,
  "reason": "AML_PY_WITNESS_BUNDLE_VALID"
}
```

## What it checks

- receipt SHA-256;
- browser-evidence SHA-256;
- whole witness-bundle SHA-256;
- challenge schema, nonce and expiry;
- challenge/evidence equality inside the session attestation;
- P-256 public key is on curve;
- public-JWK SHA-256 fingerprint;
- raw 64-byte P-256 ECDSA signature over the canonical attestation payload.

## Deliberate separation

This implementation does **not** import:

- `docs/aml-browser-integrity.js`
- `docs/aml-browser-evidence.js`
- `docs/aml-session-attestation.js`
- `docs/aml-witness-bundle.js`

That separation is intentional. A change that works only because both producer and verifier share the same bug is less useful than a contract two implementations can reproduce.

## Canonicalization boundary

The current prototype contract uses `sorted-json-v1`: recursively sorted object keys, preserved array order, and compact JSON serialization.

Cross-language numeric serialization deserves continued adversarial testing, especially non-integer and edge-case IEEE-754 values. The golden vector intentionally uses integer scores. A future canonicalization revision should be versioned rather than silently changing these bytes.

## Claim boundary

This is still maintained inside the AML repository, so it does **not** count as an independent external witness.

A PASS means this Python implementation reproduced the project-defined integrity and ECDSA checks for the exact supplied artifact. It is not identity, official certification, policy truth, or regulatory compliance.
