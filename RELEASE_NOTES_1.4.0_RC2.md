# ĀML Core v1.4.0-rc.2 — Hardened Federated Trust & Adoption Preview

`v1.4.0-rc.2` refreshes the public post-v1.3 architecture snapshot with the latest security, documentation, trust-root, ecosystem, and adoption hardening from `main`.

**Version boundary:** the stable package/CLI/capability version remains v1.3.0. This is a GitHub prerelease snapshot of the broader v1.4 candidate architecture, not a claim that stable v1.4 has been published to a package registry.

## What RC2 adds over RC1

- hardened `SECURITY.md` covering compiler/parser, policy, cryptography, federation, capability authority, HTTP, browser, and official-brand trust surfaces
- complete JavaScript API documentation matching the actual exported reference implementation
- current roadmap separating stable v1.3 from v1.4 release-candidate work
- corrected public conformance-version drift
- expanded ecosystem map across adoption, federation, trust, standards, security, browser, and official authorization
- `Why AML Now` adoption brief for developers, AI teams, researchers, enterprises, journalists, and standards participants
- explicit production ĀRU trust-root/public-key discoverability
- clarified changelog labeling so prerelease work cannot be mistaken for stable v1.4

## Architecture carried forward from RC1

### Mainstream adoption

- AI Interface Firewall™
- View Meaning™ browser inspector
- privacy-minimal View Meaning browser-extension prototype
- React-compatible accountable UI adapter
- plain-JavaScript, React, and Next.js starter kits
- Meaning Gate™ GitHub Action
- Verify Official ĀML GitHub Action
- dependency-free AML HTTP service with OpenAPI contract
- 30-minute enterprise pilot kit

### Trust continuity

- expiring and revocable consent ledgers
- policy consensus with explicit dissent
- semantic risk scoring
- multi-policy matrices
- signed audit checkpoints
- attention-ledger integrity verification
- execution provenance graphs
- Merkle-batched receipt inclusion proofs

### Cross-system interoperability

- runtime capability negotiation
- portable policy passports
- content-addressed bundles
- selective-disclosure commitments
- `aml-wire/1`
- federated AML exchange
- causal execution graphs
- canonical JSON serialization
- golden protocol vectors
- replay resistance

### Trust fabric

- delegated trust chains
- M-of-N threshold authorization
- append-only transparency logs
- bounded signed capability tokens
- revocation registries
- Proof-Carrying Interface™ manifests
- machine-verifiable conformance claims
- layered compatibility from Core through Governed

### Official AML verification

- machine-readable mark and authorization registries
- signed `aml-brand-authorization/1` credentials
- canonical ĀRU trust-root registry
- browser, CLI, HTTP, and GitHub Action verification
- first production ĀRU Ed25519 public verification key/fingerprint
- production private signing material intentionally kept outside GitHub

A self-signed credential can be cryptographically valid while still **not** being an official ĀRU authorization. Official verification additionally requires an active, non-revoked signer fingerprint in the canonical ĀRU trust-root registry.

## Standards surface

- RFCs 0001–0011
- protocol discovery
- versioned registries
- JSON Schemas
- conformance levels and fixtures
- canonical vectors
- independent second-runtime challenge
- explicit governance and standardization path

## Try AML now

- Playground: https://aruintelligence.github.io/aml-core/playground.html
- View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html
- Official AML verifier: https://aruintelligence.github.io/aml-core/official-verify.html
- Official AML / licensing: https://aruintelligence.github.io/aml-core/official-aml.html
- Enterprise pilot: `pilots/enterprise-30min/`
- Why AML Now: `docs/WHY_AML_NOW.md`
- Full API: `API.md`
- Ecosystem map: `ECOSYSTEM.md`

## Verify the repository

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
npm run check:links
npm test
npm run benchmark
```

The AML Conformance workflow independently checks the public conformance surface.

## Open-source and brand boundary

Covered software remains MIT licensed. Official ĀML™ / ĀRU™ branding, logos, compatibility branding, certification-style identity, endorsement, OEM/co-branding, and related reserved brand rights are separate from the software license.

Technical conformance does not by itself imply official authorization, endorsement, partnership, certification, or trademark rights.

## Evidence boundary

ĀML improves software-level inspectability, policy control, reproducibility, interoperability, and cryptographic integrity. It does not establish that current attention/restoration values objectively measure cognition or wellbeing, does not make an AI's declared intent truthful, and does not replace WCAG conformance or assistive-technology testing.

Cryptographic signatures prove integrity and key possession. They do not prove moral correctness or institutional trust by themselves.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**.
