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

## Current bootstrap state

`BRAND_TRUST_ROOTS.json` is intentionally published with `status: "unprovisioned"` until an actual production public-key fingerprint is deliberately established.

Until a production key is provisioned, **no test key, example credential, or self-signed credential should be represented as official AML authorization.**

## Production key generation

Production signing keys should be generated in a controlled environment using a reputable cryptographic implementation that supports Ed25519.

Recommended operational properties:

- generate the key outside the public repository;
- restrict filesystem/account access;
- encrypt backups;
- maintain an offline or hardware-protected copy where practical;
- document the key's purpose and creation date;
- publish only the public key/fingerprint;
- do not use the same private key for unrelated infrastructure;
- consider separate keys for brand authorization, release signing, and other trust domains.

## Provisioning a trust root

Before treating credentials as official:

1. create the production Ed25519 key securely;
2. derive the SHA-256 fingerprint of the SPKI DER public key using the same representation used by AML verification;
3. add the public fingerprint to `BRAND_TRUST_ROOTS.json` under `active_keys`;
4. assign a stable `key_id` and purpose;
5. record `not_before` and optionally `not_after` timestamps;
6. merge/publish the registry through the canonical AML repository;
7. independently verify the published fingerprint from a separate machine/account before issuing credentials.

A public-key PEM may be published separately if desired, but the fingerprint is the minimum trust-binding field used by the current verifier.

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
