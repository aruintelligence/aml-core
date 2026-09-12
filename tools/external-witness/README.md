# ĀML external witness kit

This directory is for independent reproduction evidence, not project self-attestation.

## Goal

An outside engineer should be able to test an exact ĀML commit, publish `PASS`, `FAIL`, or `MIXED`, optionally sign the result with their own Ed25519 key, and provide evidence without granting ĀRU control over the witness identity or key.

## Minimal flow

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
git checkout <exact-commit>
node tools/external-witness/aml-external-witness.mjs template aruintelligence/aml-core <exact-commit> PASS > witness.json
# replace all placeholders and attach hashes of your actual evidence
node tools/external-witness/aml-external-witness.mjs verify witness.json
```

Optional signing uses a witness-owned Ed25519 key:

```bash
node tools/external-witness/aml-external-witness.mjs sign witness.json witness-private.pem witness-signed.json
node tools/external-witness/aml-external-witness.mjs verify witness-signed.json
```

Do **not** publish a private key. The signed envelope contains only the derived public key, its SHA-256 fingerprint, and the signature.

## What counts

Useful evidence includes command transcripts, machine-readable reports, source patches, clean-room implementation output, screenshots that corroborate a reproducible command, or immutable external artifacts. Hash every evidence item you reference.

A result should be `PASS` only when the claimed behavior reproduced as documented, `FAIL` when it did not, and `MIXED` when some material claims reproduced and others did not.

## Trust boundary

A valid Ed25519 signature proves possession of the corresponding private key for the canonical submission bytes. It does **not** by itself prove identity, independence, competence, adoption, certification, scientific validity, or standards status. Those are separate verifier judgments.

Project-maintained CI fixtures are synthetic and never count as independent evidence.

## Public intake

Use GitHub issue #88 or the repository's **External witness result** issue form. Publish the exact tested commit, result, reproduction command, environment, evidence links/hashes, and whether your submission is signed.

Never include secrets, credentials, tokens, private keys, personal data you do not intend to publish, or confidential employer/customer information.
