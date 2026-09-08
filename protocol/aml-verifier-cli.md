# AML Verifier CLI Contract

**SPEC — experimental project contract.**

Purpose: make independent `aml-witness-bundle/1` verification easy to automate without importing AML implementation internals.

## Invocation

A verifier SHOULD accept one witness-bundle JSON file path:

```text
<verifier-command> bundle.json
```

A verifier MAY accept a fixed verification time for public vectors:

```text
<verifier-command> --now 2030-01-01T00:05:00Z bundle.json
```

## Output

Write one JSON object to stdout:

```json
{
  "valid": true,
  "reason": "IMPLEMENTATION_DEFINED_SUCCESS_REASON"
}
```

Required fields:

- `valid`: boolean
- `reason`: non-empty string

Additional fields are allowed by an implementation, but conformance tooling must not require them.

## Exit status

- `0` — artifact passed the implementation's verification checks
- nonzero — artifact failed verification or could not be processed

## Minimum behavioral tests

An implementation claiming this CLI contract MUST demonstrate:

1. canonical golden witness vector -> exit `0`, `valid: true`;
2. mutation of a receipt-bound field -> nonzero, `valid: false`;
3. expired verifier challenge -> nonzero, `valid: false`;
4. wrong challenge binding -> nonzero, `valid: false`.

## Interoperability rule

The verifier must implement the published contracts rather than importing the reference verifier under test.

Canonical inputs:

- `protocol/aml-witness-bundle.schema.json`
- `protocol/aml-browser-evidence.schema.json`
- `protocol/aml-session-attestation.schema.json`
- `protocol/aml-verification-challenge.schema.json`
- `protocol/sorted-json-v1.md`
- `independent/python/witness-vector.json`

## Claim boundary

Passing this CLI contract is project-defined technical compatibility evidence. It is not certification, standards-body approval, proof of institutional independence, proof of truthful declared intent, or official AML trademark authorization.
