# The page does not get to grade itself anymore

**Status: PITCH**

ĀML browser evidence can now leave the page that generated it.

The verifier creates a random challenge first. The page must bind that exact challenge to its exact evidence hash with a fresh ephemeral browser session signature. The bundle is then checked on a separate verifier page.

Try it:

https://aruintelligence.github.io/aml-core/detached-verifier.html

Producer:

https://aruintelligence.github.io/aml-core/attest-evidence.html

The prototype checks:

```text
browser evidence hash
+ verifier challenge
+ challenge expiry
+ session public-key fingerprint
+ ECDSA signature
+ whole witness-bundle hash
```

Then mutate the copied evidence and verify it again.

This is not identity proof, official certification, regulatory compliance, or proof that declared intent is truthful. It is a reproducible cryptographic binding experiment for interface evidence.

Open it. Generate a challenge. Verify the bundle. Tamper with it. File what happened.
