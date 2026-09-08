# ĀRU AML Public Signing Keys

This directory contains **public verification material only**.

## Active production AML brand-signing key

- key ID: `aru-aml-brand-prod-2026-09-08-01`
- algorithm: Ed25519
- public PEM: `aru-aml-brand-prod-2026-09-08-01-public.pem`
- SPKI DER SHA-256 fingerprint: `eda0184568cb2110add5130d2a9fffaf53a77e0f2be311be414e7912ed69997c`
- purpose: Official ĀML brand authorization and certification credential signing
- canonical status source: `../BRAND_TRUST_ROOTS.json`

## Security boundary

No private signing key belongs in this repository.

A public key being present here is not, by itself, sufficient to establish official trust. Verifiers must also confirm that its fingerprint is active and non-revoked in the canonical `BRAND_TRUST_ROOTS.json` registry.

If a private key is ever exposed, its public fingerprint must be moved to the revoked-key list and a replacement trust root provisioned before further official credentials are issued.
