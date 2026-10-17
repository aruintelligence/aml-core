# ĀML Session Attestation

**Status: SHIPPED reference prototype**

ĀML browser evidence can now leave the page and be checked against a verifier-generated challenge.

## Flow

```text
verifier creates random challenge
        ↓
page creates sealed AML browser evidence
        ↓
page signs evidence hash + challenge nonce and expiration
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

The producer generates a fresh P-256 key for each attestation and requests a
nonextractable private key from Web Crypto. Its public key remains exportable
for offline verification. Sequential and overlapping requests therefore do
not reuse a page-wide fingerprint or compete over a mutable signing key.
`resetAMLSessionKey()` still clears the last published attestation for callers
using that helper; there is no cached signing key to reset. Existing consumers
that grouped multiple attestations by one page-wide session fingerprint must
use an explicit, separately justified correlation mechanism instead.
Different fingerprints do not prove different people, browsers, or sessions.

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

The verifier accepts a challenge only from its issue time through its expiration time, inclusive. An invalid verifier clock fails closed. An archived witness bundle remains evidence of what was signed, but a later verifier should not describe an expired challenge as freshly verified. Challenge creation requires a positive integer duration in milliseconds.

Challenge timestamps must have the exact UTC millisecond spelling generated
by this API. Other ISO-8601 spellings, including offsets or extra precision,
and normalized invalid dates are rejected by both project-authored verifiers.
This narrows their input profile without changing the frozen historical schema;
it does not make the machine clock a trusted time source.

The reference verifiers also require exactly the five fields emitted by the
challenge generator and a canonically encoded 32-byte nonce. This rejects
extra unsigned issuer claims and ambiguous nonce spellings. Older custom
challenges outside this profile must be regenerated. The encoding check
cannot establish the quality of the verifier's randomness.

The session signature covers the challenge nonce and expiration, not its
`issued_at` field. A detached verifier should retain the challenge it
generated and call `verifyWitnessBundle(bundle, { expectedChallenge })` to
compare the entire challenge against its own copy.

The raw P-256 signature and public-key coordinates use unique unpadded
base64url encodings. The verifier rejects padding, whitespace, truncation,
and altered unused encoding bits, even if a permissive decoder would produce
the original bytes. This keeps witness verification consistent across the
JavaScript and project-authored Python implementations.

## Try it

- Detached verifier: https://aruintelligence.github.io/aml-core/detached-verifier.html
- Attestation producer: https://aruintelligence.github.io/aml-core/attest-evidence.html
- Browser evidence demo: https://aruintelligence.github.io/aml-core/browser-evidence-demo.html

## External challenge

Implement the same verification flow independently. Do not import the reference verifier. Any mismatch is specification feedback.
