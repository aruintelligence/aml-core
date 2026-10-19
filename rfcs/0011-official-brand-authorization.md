# RFC 0011 — Official AML Brand Authorization Credentials

Status: Draft

## Abstract

This RFC defines a cryptographically verifiable credential for recording the scope of an official written authorization to use reserved ĀML™ / ĀRU™ branding.

The credential does **not** create trademark rights by itself and does not replace the underlying written agreement. It provides machine-verifiable evidence of the issuer, grantee, authorized marks, permitted uses, term, and credential integrity.

## Credential type

`aml-brand-authorization/1`

Required semantic fields:

- issuer
- grantee
- authorization_id
- marks
- permitted_uses
- issued_at
- expires_at
- agreement_reference

Integrity fields:

- credential_hash
- algorithm
- public_key_pem
- public_key_sha256
- signature_base64

## Verification

A verifier MUST:

1. canonicalize the unsigned credential body;
2. recompute the SHA-256 credential hash;
3. verify the Ed25519 signature;
4. verify the public-key fingerprint;
5. capture a verification instant from the local clock when no explicit as-of time is supplied; reject credentials before `issued_at` and at or after `expires_at` (the end is exclusive);
6. reject credentials whose hash appears in an authoritative revocation registry when such a registry is supplied; report when no credential revocation source was checked.

An official signer check also requires a trusted active root whose validity window contains the same verification instant. An explicit caller-supplied time is a historical as-of check and does not establish the current state of a credential or trust root. Key-level revocation and per-credential revocation are distinct checks.

For an exact-use claim, the buyer can separately pin the canonical SHA-256 of the trust registry and the revocation registry head in an `aml-brand-claim-policy/1` record. `verifyBrandClaim` checks the pinned snapshots at its local clock and requires an exact grantee, mark, and permitted use. `claim_verified` refers to the supplied, pinned snapshots only; it is not a freshness guarantee. A hash chain without a buyer-held head can be rolled back to a valid prefix. The buyer must obtain and refresh both pins independently of the credential presenter.

## Legal boundary

A valid cryptographic credential proves that the holder possesses a credential signed by the represented key and that the credential has not been modified. It does not independently prove:

- ownership of a trademark;
- validity of a trademark registration;
- enforceability of the underlying contract;
- the authority of a signer unless the verifier independently trusts that key;
- that the credential has not been superseded outside the supplied revocation source.

Official brand rights remain governed by the written agreement and applicable law.

## Open-source boundary

The MIT software license and official brand authorization remain separate. No brand credential is required merely to exercise rights granted by the MIT License.

## Commercial purpose

This credential allows an enterprise, OEM, integration partner, or officially authorized compatibility program to present a verifiable record of its authorized use without turning open technical conformance into a closed protocol.
