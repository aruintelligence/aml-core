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

The same fixed signatures have a buyer-held trust-group example:

```bash
python3 independent/python/verify_signed_quorum.py \
  independent/python/signed-quorum-vector.json \
  --policy independent/python/signed-quorum-held-group-policy-vector.json
```

A material-pinned version 3 policy is also checked against those fixed
signatures:

```bash
python3 independent/python/verify_signed_quorum.py \
  independent/python/signed-quorum-vector.json \
  --policy independent/python/signed-quorum-held-material-policy-vector.json
```

The fixture policy sits beside the quorum for test convenience; in a real
decision, retain your policy separately before receiving the quorum. The
fixture has no underlying witness artifact and does not test witness replay.

The Python and JavaScript CLIs also accept the version 2 buyer-held policy
documented in [Verifier Plurality](../../docs/VERIFIER_PLURALITY.md). It pins
each allowed key fingerprint to a buyer-defined trust group and requires both
distinct key material and the specified number of distinct groups. Assigning
group labels in a local policy does not establish the real-world identity or
independence of their operators. Version 3 additionally pins each public
key's material fingerprint and rejects duplicate material pins in the held
roster. Use `aml fingerprint-verifier-key <public-jwk.json>` on a separately
obtained public key document to derive both fingerprints.

For an actual `aml-witness-bundle/1`, also supply the saved bundle and the
challenge you retained before receiving it:

```bash
python3 independent/python/verify_signed_quorum.py saved-quorum.json \
  --policy held-policy.json \
  --bundle witness.json --challenge held-challenge.json
```

`valid` means the quorum is internally consistent; `threshold_met` means its
own endorsement threshold was reached. `policy_met` pins the expected artifact
and trusted verifier keys, and optionally requires buyer-held trust-group
diversity with policy version 2. `witness_met` requires
a valid bundle at the current time, a matching retained challenge, and the
exact bundle type and hash named by the quorum. `replayable_claims_consistent`
rejects authenticated positive reports whose explicit session fingerprint,
challenge expiry, claimed check time, or reference check results contradict
the replay. A stated `checked_at` must be canonical UTC milliseconds inside
the challenge's validity interval and at or after the bundle and attestation
creation times, which must also be canonical UTC milliseconds for this
comparison. This checks artifact and signer assertions for consistency; it
does not authenticate when the signer performed the check. All five
are separate results; a valid quorum can fail any later condition. Supplying
only a bundle or only a challenge is a usage error.

Held policy version 6 adds `required_key_material_fingerprints`, a nonempty
subset of the pinned roster. Each must appear in an authenticated supplied
report over the expected artifact; an invalid signature cannot establish
presence, and a negative report still triggers the inherited version 5 veto.
The policy evaluation lists missing required material. This detects omission
of a named participant from the supplied quorum, not why it is missing or
whether other reports from a present key were withheld.

The imported `verify_signed_quorum.verify_quorum(...)` function applies the
same held-policy validation and paired-input requirement. It raises
`ValueError` for invalid verifier-held configuration before evaluating a
quorum. A zero-threshold policy or an unpaired witness bundle cannot produce
a passing result through the direct Python API.

The quorum result includes `input_fingerprints` for the canonical JSON quorum
and each supplied held policy, bundle, and challenge. These are SHA-256 hashes
of complete `sorted-json-v1` JSON values, not hashes of the source file bytes.
The JavaScript and Python comparison harness checks their agreement, including
changed held policies and challenges. An unsupported input has no portable
input binding. For a structurally checkable quorum with witness inputs,
`witness_evaluation.evaluated_at` is the UTC millisecond instant sampled once
from the verifier's local clock and used for challenge freshness. The
`clock_source` is `local_system`. A failed witness replay records this instant
too. It is an unsigned observation, not a trusted timestamp or evidence of
when the signer checked; retain the inputs and evaluate again for a current
decision. These hashes identify evaluated content, not an independent
certification.

To turn independently retained fingerprints into an acceptance gate, pass a
strict `aml-signed-quorum-input-expectations/1` JSON file with one or more
canonical SHA-256 fields to `--expect-inputs held-inputs.json`. Use
`aml fingerprint-json held-policy.json` and the same command for your retained
challenge to derive their `policy_sha256` and `held_challenge_sha256` values
before receiving the quorum. The optional `quorum_sha256` and
`witness_bundle_sha256` fields can pin those documents too. `inputs_met`
checks only the fields present in this separately controlled file; the
`input_evaluation` lists mismatches. A valid quorum and satisfied policy can
still fail this additional condition with exit `2`. Invalid expectations or
a pin for an absent input produce usage exit `1`. The Python verifier uses its
documented narrower portable JSON subset.

Exit `0` requires internal validity, the saved threshold, and every held
condition supplied. Exit `2` means a verification condition failed; exit `1`
means unreadable JSON, missing paired inputs, or invalid held configuration. Run
`node scripts/check-signed-quorum-python.mjs` to compare its results against
JavaScript on signed fixtures, including dissent, tampering, key metadata
aliases, untrusted keys, live witness replay, and contradictory signed claims.
Use `--decision-only` with either CLI to print the small, unsigned
`aml-signed-quorum-decision/1` projection instead of report bodies, notes,
signatures, or raw error strings. It retains the checked booleans, input
fingerprints when available, expectations-file hash when supplied, and the
local witness evaluation instant when replayed. Exit codes are unchanged;
the full result remains available without the flag. Input hashes do not hide
low-entropy input values or establish custody.

The Python quorum verifier accepts only the stated cross-language safe
canonicalization domain: safe integers, no floating-point values, BMP
object keys except JavaScript array-index keys, and strings without unpaired
surrogates. Public JWK coordinates and signatures must use canonical
unpadded base64url. It rejects duplicate JSON keys. A rejection outside this
subset does not imply the default JavaScript verifier rejects the same object.
Use `aml verify-signed-quorum saved-quorum.json --portable` or the JavaScript
API's `portable: true` option to require the narrower profile as a separate
acceptance condition. The CLI also rejects fractional numeric spellings such
as `1.0` before JavaScript parsing; the API cannot recover source spelling.
The same cross-language domain applies to Python witness replay. Unknown report check
names and signer process claims such as `verifier_held_challenge` are not
inferred from a local replay.

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

For a current witness, supply `--challenge held-challenge.json` to check a
separately retained challenge as well. `--now` overrides the current time for
test fixtures only; a historical override is not a live freshness check.

## What it checks

- receipt SHA-256;
- browser-evidence SHA-256;
- whole witness-bundle SHA-256;
- exactly the generated five challenge fields, `prototype: true`, and a
  uniquely encoded 32-byte nonce (43 unpadded base64url characters);
- challenge issue and expiry in exact UTC milliseconds, rejecting calendar
  rollover, offset aliases, and extra fractional precision before freshness;
- equality with a separately retained, fresh challenge when supplied;
- challenge/evidence equality inside the session attestation;
- canonical UTC millisecond evidence, attestation, and bundle times (and a
  receipt time if present), with claimed order from receipt through evidence,
  attestation, bundle creation, and the local replay clock;
- P-256 public key is on curve;
- public-JWK SHA-256 fingerprint;
- raw 64-byte P-256 ECDSA signature over the canonical attestation payload.

The session signature and both 32-byte public-key coordinates must have their
unique unpadded base64url spelling. The JavaScript witness verifier enforces
the same byte lengths and round-trip encoding checks; a changed unused bit,
padding, or whitespace cannot be accepted by one implementation alone.
Nonce encoding does not attest to the quality of randomness. Custom historical
challenges outside the generator's shape need to be regenerated for this
reference verifier profile; the frozen schema is unchanged.

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
