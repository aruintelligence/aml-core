# ĀML Session Attestation

**Status: SHIPPED reference prototype**

ĀML browser evidence can now leave the page and be checked against a verifier-generated challenge.

## Flow

```text
verifier creates random challenge
        ↓
page creates sealed AML browser evidence
        ↓
page signs evidence hash + verifier challenge
with an ephemeral P-256 browser key
        ↓
page exports aml-witness-bundle/1
        ↓
detached verifier checks:
- evidence SHA-256
- challenge freshness
- challenge equality
- session public-key fingerprint
- ECDSA signature
- bundle SHA-256
```

## Why this exists

A page that creates and verifies its own receipt is useful for debugging, but a skeptical verifier should be able to generate the freshness challenge itself and verify the resulting artifact separately.

## Browser APIs

```js
import { createVerificationChallenge } from './aml-verification-challenge.js';
import { createSessionAttestation, verifySessionAttestation } from './aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle } from './aml-witness-bundle.js';
```

## Claim boundary

A valid `aml-session-attestation/1` proves that the holder of an ephemeral browser session private key signed the exact bound evidence hash and verifier challenge.

It does **not** prove:

- who the human is;
- which organization controls the browser;
- that declared purpose is truthful;
- that attention or restoration scores are objective measurements;
- that a policy is morally correct;
- that the artifact is officially authorized by ĀRU;
- regulatory compliance.

Official ĀRU brand authorization uses a separate trust-root system.

## Freshness

The verifier challenge expires. An archived witness bundle remains evidence of what was signed, but a later verifier should not describe an expired challenge as freshly verified.

## Try it

- Detached verifier: https://aruintelligence.github.io/aml-core/detached-verifier.html
- Attestation producer: https://aruintelligence.github.io/aml-core/attest-evidence.html
- Browser evidence demo: https://aruintelligence.github.io/aml-core/browser-evidence-demo.html

## External challenge

Implement the same verification flow independently. Do not import the reference verifier. Any mismatch is specification feedback.
