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
5. reject expired credentials when a verification time is supplied;
6. reject credentials whose hash appears in an authoritative revocation registry when such a registry is supplied.

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
