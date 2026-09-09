# Signed ĀML Meaning Manifest

**Status: preview implementation; experimental protocol surface, not a ratified standard**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

A Meaning Manifest locks the compiled AMT identity of an exact set of ĀML files. A Signed Meaning Manifest adds a detached Ed25519 attestation over that semantic project root and its attribution metadata.

## What is signed

The attestation protocol is:

```text
aml-meaning-manifest-attestation/1
```

Its canonical signed material binds:

- attestation protocol and version;
- Ed25519 algorithm identifier;
- Meaning Manifest protocol/version;
- Meaning Manifest material protocol;
- Meaning Fingerprint protocol;
- project `manifest_root_sha256`;
- locked file count;
- signer label;
- signing time.

Before signing, ĀML recomputes the Meaning Manifest root from the manifest file entries. An internally inconsistent manifest is refused rather than cryptographically endorsed.

The public-key fingerprint is SHA-256 over the raw SPKI DER bytes of the Ed25519 public key.

## Shell workflow

Generate a semantic lockfile:

```bash
aml-meaning manifest ui/home.aml ui/settings.aml > aml-meaning-lock.json
```

Sign it:

```bash
aml-meaning sign-manifest aml-meaning-lock.json release-private.pem release-engineering > aml-meaning-attestation.json
```

Verify the detached attestation:

```bash
aml-meaning verify-attestation aml-meaning-attestation.json aml-meaning-lock.json
```

Then separately verify the lockfile against current source:

```bash
aml-meaning verify-manifest aml-meaning-lock.json
```

That separation is deliberate. Cryptographic attribution and source-to-manifest semantic integrity are distinct claims.

## Verification model

A successful signed-manifest verification requires all of the following:

1. the Meaning Manifest is internally well-formed;
2. its declared root matches a fresh root recomputed from its file entries;
3. the attestation metadata names that exact manifest contract/root/file count;
4. the public-key fingerprint matches the supplied Ed25519 public key;
5. the Ed25519 signature verifies over canonical signed material.

Only then is `attribution_bound` true and the signer/time returned as authenticated fields.

Changing the signer, timestamp, root, file count, protocol metadata, public key, or signature causes verification to fail.

## Evidence boundary

This proves possession of the private key used to sign the exact attestation material and integrity of the referenced Meaning Manifest root under the declared ĀML contracts. It does **not** prove that the signer is institutionally legitimate, that declared meaning is truthful, that the interface is ethical or legal, or that ĀML is a ratified standard.
