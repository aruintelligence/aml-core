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

## One-script API

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml.js"></script>
```

The bootstrap exposes the prototype browser API as `window.AML` (also available as `AML` in ordinary page scripts).

```js
const challenge = window.AML.createChallenge();
const attestation = await window.AML.attest({ challenge });
const bundle = await window.AML.createWitnessBundle({ challenge, attestation });
const check = await window.AML.verifyWitnessBundle(bundle);
```

## Claim boundary

A valid result shows that the project-defined cryptographic checks passed for the exact supplied artifact and challenge.

It does not prove identity, official authorization, ethical correctness, truthful declared meaning, or regulatory compliance.

Open the demo. Generate a challenge. Verify a bundle. Tamper with it. File what happened.
