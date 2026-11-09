# Go witness verifier

**SHIPPED reference implementation.**

This directory verifies the public `aml-witness-bundle/1` contract using only the Go standard library. It does not import the JavaScript or Python AML verifier.

Run the golden vector:

```bash
cd independent/go
go run . --now 2030-01-01T00:05:00Z ../python/witness-vector.json
```

Expected result (abridged), exit status `3`:

```json
{
  "valid": true,
  "reason": "AML_GO_WITNESS_BUNDLE_VALID",
  "authorized": false
}
```

This verifier has no held-challenge input and does not trust a caller
`--now`, so it never authorizes: a valid bundle exits `3`, an invalid one `1`,
an input error `2`. `--diagnostic-only` exits `0` for a valid bundle and
reports `NOT AN AUTHORIZATION DECISION`; the black-box conformance harness
uses that mode. `verify.sh` builds the binary and preserves its exit code
(`go run` would report every failure as `1`). See
[docs/COMMAND_AUTHORIZATION.md](../../docs/COMMAND_AUTHORIZATION.md).

The implementation checks:

- `sorted-json-v1` canonical JSON for the published safe domain;
- SHA-256 receipt integrity;
- SHA-256 browser-evidence integrity;
- SHA-256 witness-bundle integrity;
- verifier challenge expiry and binding;
- P-256 public JWK validity;
- session-key fingerprint;
- raw 64-byte ECDSA P-256 / SHA-256 signature.

## Why this exists

The same public artifact should not depend on one language runtime. The reference repository now carries JavaScript, Python, and Go verification paths so cross-runtime disagreements become testable.

## What this does not prove

This implementation is maintained inside `aruintelligence/aml-core`, so it **does not count as an independent external witness or third-party adoption**.

A PASS proves only the project-defined integrity, freshness, binding, and signature checks for the supplied artifact. It does not prove identity, truthful declared intent, policy quality, institutional independence, official ĀRU authorization, or regulatory compliance.
