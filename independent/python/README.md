# Dependency-Free Python Witness Verifier

**Status: SHIPPED reference interoperability implementation**

This directory implements `aml-witness-bundle/1` from the public contracts without importing the AML JavaScript runtime.

It uses only the Python standard library, including a compact P-256 ECDSA verifier implemented directly from the published public JWK coordinates.

## Verify a saved signed quorum

It also includes a standalone saved signed-quorum verifier. It recomputes
P-256 signatures, summary counts, distinct public-key material, and a separate
verifier-held artifact/key policy:

```bash
python3 independent/python/verify_signed_quorum.py saved-quorum.json --policy held-policy.json
```

Reproduce the fixed synthetic vector:

```bash
python3 independent/python/verify_signed_quorum.py \
  independent/python/signed-quorum-vector.json \
  --policy independent/python/signed-quorum-held-policy-vector.json
```

The fixture policy sits beside the quorum for test convenience; in a real
decision, retain your policy separately before receiving the quorum. The
fixture has no underlying witness artifact and does not test witness replay.

Exit `0` requires internal validity, the saved threshold, and the held policy
if supplied. Exit `2` means a verification condition failed; exit `1` means
unreadable JSON or invalid held configuration. Run
`node scripts/check-signed-quorum-python.mjs` to compare its results against
JavaScript on signed fixtures, including dissent, tampering, key metadata
aliases, and untrusted keys.

The Python quorum verifier accepts only the stated cross-language safe
canonicalization domain: safe integers, no floating-point values, and BMP
object keys. Public JWK coordinates and signatures must use canonical
unpadded base64url. It rejects duplicate JSON keys. A rejection outside this subset
does not imply the JavaScript verifier rejects the same object. It does not
replay witness bundles or retained challenges; use the JavaScript verifier
with `--bundle` and `--challenge` for those additional checks.

## Verify the golden witness vector

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
