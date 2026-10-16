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
- challenge expiration;
- evidence-hash equality;
- ephemeral P-256 public-key fingerprint;
- ECDSA P-256 / SHA-256 signature;
- whole `aml-witness-bundle/1` integrity.

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
from the untrusted bundle would defeat the verifier-held comparison. This
command is in the current preview checkout, not the pinned `v1.3.0` stable
package.

## Claim boundary

A valid result shows that the project-defined cryptographic checks passed for the exact supplied artifact and challenge.

It does not prove identity, official authorization, ethical correctness, truthful declared meaning, or regulatory compliance.

Open the demo. Generate a challenge. Verify a bundle. Tamper with it. File what happened.
