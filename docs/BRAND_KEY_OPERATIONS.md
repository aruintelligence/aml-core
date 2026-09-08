# ĀML™ Official Brand Signing — Key Operations

This document defines the operational boundary for cryptographic credentials representing official AML/ĀRU brand authorization.

## Core rule

**Never commit a production private signing key to this repository, Base44, a public issue, a browser bundle, example code, or a shared document.**

The canonical repository should publish only the public information necessary to verify official credentials.

## Trust model

A valid `aml-brand-authorization/1` signature proves only that the credential was signed by the embedded key.

An authorization should be treated as **officially authorized by ĀRU Intelligence Inc.** only when all of the following are true:

1. credential hash/integrity is valid;
2. Ed25519 signature is valid;
3. credential is not expired;
4. credential is not revoked in the applicable credential revocation source;
5. signing-key fingerprint appears in the canonical `BRAND_TRUST_ROOTS.json` active-key list;
6. signing-key fingerprint does not appear in the revoked-key list;
7. the credential scope matches the use being claimed;
8. the underlying written agreement is valid for the represented use.

## Current production trust root

The first production AML brand-signing trust root is active.

- key ID: `aru-aml-brand-prod-2026-09-08-01`
- algorithm: Ed25519
- public-key SHA-256 fingerprint: `eda0184568cb2110add5130d2a9fffaf53a77e0f2be311be414e7912ed69997c`
- public key: `keys/aru-aml-brand-prod-2026-09-08-01-public.pem`
- canonical trust registry: `BRAND_TRUST_ROOTS.json`

The corresponding production private key was generated outside GitHub and is **not** stored in this repository or Base44.

A credential should not be represented as official merely because it is self-signed. Official verification requires the credential signature to validate and the signer fingerprint to be active and non-revoked in the canonical trust registry.

## Production key handling

Production signing keys should be generated and held in a controlled environment using a reputable cryptographic implementation that supports Ed25519.

Operational requirements:

- keep the private key outside public repositories;
- restrict filesystem/account access;
- make encrypted offline backups;
- maintain a second protected backup where practical;
- document the key's purpose and creation date;
- publish only the public key/fingerprint;
- do not use the same private key for unrelated infrastructure;
- use separate keys for brand authorization, release signing, and other trust domains where practical.

## Independent verification after provisioning

After publishing a trust root:

1. read `BRAND_TRUST_ROOTS.json` from the canonical repository;
2. independently derive SHA-256 of the SPKI DER bytes from the published public PEM;
3. confirm the derived fingerprint equals the registry fingerprint;
4. verify CI still rejects any private-key material under `keys/`;
5. issue a test credential outside the public repository and verify it with `aml-brand-verify` or the public verifier before using the key in a real agreement.

## Issuing an authorization

An official credential should only be issued after an appropriate written authorization exists.

The credential should use:

- an unambiguous grantee legal/business name;
- explicit marks;
- narrow permitted-use categories;
- a stable authorization ID;
- an agreement reference that does not expose confidential contract terms;
- issue and expiration timestamps where appropriate.

Do not encode confidential pricing, customer data, trade secrets, or private agreement text into a public credential.

## Revoking a credential

If a specific authorization ends or is compromised:

- revoke the credential hash using the AML revocation-registry mechanism;
- publish the revocation source if public verification depends on it;
- record a non-confidential reason where appropriate.

## Revoking a signing key

If a private key is lost, exposed, or should no longer be trusted:

1. stop issuing credentials immediately;
2. move the fingerprint from `active_keys` to `revoked_keys` in `BRAND_TRUST_ROOTS.json`;
3. include a revocation time and non-sensitive reason;
4. generate/provision a new key;
5. reissue active credentials only after reviewing the underlying agreements;
6. communicate the rotation to affected partners.

A key-level revocation invalidates the key as an official trust root even if individual embedded signatures remain cryptographically valid.

## Key rotation

Routine rotation can overlap old/new active keys for a controlled period. Each active key should have an explicit purpose and validity window.

Avoid silently changing fingerprints. Trust-root changes should be visible in canonical repository history.

## Multi-party control

For high-value brand/certification operations, AML already includes threshold-authorization primitives. A future production program can require multiple authorized people/keys to approve sensitive operations such as:

- adding a new trust root;
- revoking a trust root;
- authorizing a high-profile certification program;
- changing official conformance-brand rules.

The current trust-root file does not claim that multi-party governance is already operational.

## Legal boundary

Cryptographic verification does not replace trademark registration, contract formation, legal authority, or legal advice. It provides technical evidence about integrity, key possession, trust-root membership, scope, and revocation state.

Official AML commercial contact: **Office@aruintelligence.com**
