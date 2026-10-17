# Detached ĀML Verification

**Status: SHIPPED reference prototype**

## One idea

The page that generated an interface should not be the only place capable of saying its evidence is valid.

ĀML now includes a detached challenge/response path.

## Try it

1. Open https://aruintelligence.github.io/aml-core/detached-verifier.html
2. Generate a challenge.
3. Open https://aruintelligence.github.io/aml-core/attest-evidence.html
4. Paste the challenge.
5. Create the signed witness bundle.
6. Copy the bundle back into the detached verifier.
7. Verify it.
8. Tamper with the pasted copy and verify again.

Expected result:

```text
original bundle -> PASS
mutated bundle  -> FAIL
wrong challenge -> FAIL
expired challenge -> FAIL
```

## What is checked

- sealed `aml-dom-receipt/1` integrity;
- sealed `aml-browser-evidence/1` integrity;
- verifier-generated random challenge;
- challenge issue time and expiration against the verifier clock;
- evidence-hash equality;
- ephemeral P-256 public-key fingerprint;
- ECDSA P-256 / SHA-256 signature;
- whole `aml-witness-bundle/1` integrity.

The session signature must be exactly 64 raw bytes encoded as 86 unpadded
base64url characters. Each public-key coordinate must be exactly 32 bytes
encoded as 43 unpadded base64url characters. Verification decodes and
re-encodes them to reject alternate spellings (including changed unused bits)
of the same bytes. The historical JSON schema remains a broad, frozen
contract; these verifiers enforce the narrower canonical encoding profile.
JavaScript and the project-authored Python verifier apply the same rule.

Challenge issue and expiry times must use the exact UTC millisecond form
emitted by `createVerificationChallenge`, such as
`2030-01-01T00:00:02.000Z`. Calendar rollover, time-zone aliases, missing
milliseconds, and extra fractional digits are rejected before freshness is
evaluated. The historical JSON schema remains unchanged and permits a
broader date-time shape; this is the current reference verifier profile.
The local clock remains an unauthenticated input to the freshness decision.

Challenge, attestation, and witness-bundle verification reject live JavaScript
values that cannot be faithfully represented as JSON (including hidden and
symbol fields, accessors, and sparse arrays). The bundle verifier also checks
the exact integrity metadata, including the SHA-256 algorithm and
`sorted-json-v1` canonicalization. Exchange bundles as JSON; a cryptographic
PASS refers to the fields that the protocol actually binds.

## One-script API

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml.js"></script>
```

The bootstrap exposes the prototype browser API as `window.AML` (also available as `AML` in ordinary page scripts).

```js
const challenge = window.AML.createChallenge();
const expectedChallenge = structuredClone(challenge); // keep this copy on the verifier
const attestation = await window.AML.attest({ challenge });
const bundle = await window.AML.createWitnessBundle({ challenge, attestation });
const check = await window.AML.verifyWitnessBundle(bundle, { expectedChallenge });
```

Pass the challenge retained by the verifier as `expectedChallenge`. The
verifier compares the complete challenge JSON, including `issued_at`, with
the one inside the bundle. The session signature directly binds the nonce
and expiration; it does not independently sign `issued_at`. The final
bundle digest is not a keyed signature, so a verifier must keep its own
challenge to establish that the response answers its request.

The downloadable report records each verification step that passed. A false
check means that step failed or was not reached after an earlier failure; it
does not claim a separate failure for every later step. In particular,
`verifier_held_challenge` is true only when the verifier supplied its retained
challenge and the complete challenge matched. A self-contained bundle can
pass its own cryptographic checks without establishing that it answered a
verifier's request.

## Verify a saved bundle from the CLI

From a checkout or packed preview that contains this command, save the
challenge **you generated and retained** as `my-challenge.json`. Save the
response separately as `bundle.json`, then run:

```bash
node bin/aml.js verify-witness bundle.json my-challenge.json
```

An installed preview package can use `aml verify-witness` instead. The
command prints the verifier result as JSON and exits `0` for valid, `2` for
rejected evidence, and `1` for a missing file or malformed input. It requires
both files and uses the current clock for expiration; extracting a challenge
from the untrusted bundle would defeat the verifier-held comparison. The CLI
requires strict UTF-8 and rejects duplicate JSON object names in both files,
including escaped aliases and nested names, as malformed input (exit `1`). An
already-parsed JavaScript object has lost that source-byte ambiguity. This
command is in the current preview checkout, not the pinned `v1.3.0` stable
package.

After the signature and hashes pass, witness replay also checks the claimed
timeline: evidence generation, attestation issue, and bundle creation must
use exact UTC milliseconds. A receipt's generation time must also use that
spelling when present. The receipt cannot postdate its evidence; evidence
cannot postdate its signed attestation; the attestation cannot predate the
challenge issue; and bundle creation must follow the attestation, precede
challenge expiry, and have occurred by the verifier's replay clock. These
fields are supplied claims, not trusted timestamps. A resealed bundle with
an impossible timeline is rejected even when its signature remains valid.

## Claim boundary

A valid result shows that the project-defined cryptographic checks passed for the exact supplied artifact and challenge.

It does not prove identity, official authorization, ethical correctness, truthful declared meaning, or regulatory compliance.

Open the demo. Generate a challenge. Verify a bundle. Tamper with it. File what happened.
