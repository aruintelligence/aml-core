# ĀML Core v1.4.0-rc.1 — Federated Trust & Mainstream Adoption Preview

This prerelease snapshots the major post-v1.3 architecture now present on `main`.

**Version boundary:** the stable package/CLI/capability version remains v1.3.0 until the package manifest is advanced through the approved package-release path. This GitHub prerelease is a public architecture and interoperability snapshot, not a claim that the v1.4 package has been published to a registry.

## What this release candidate adds beyond v1.3

### Mainstream adoption

- AI Interface Firewall™ for placing AML between AI/app intent and a human-facing interface
- View Meaning™ browser inspector
- privacy-minimal View Meaning browser-extension prototype
- React-compatible accountable UI adapter
- plain-JavaScript, React, and Next.js starter kits
- Meaning Gate™ GitHub Action
- Verify Official ĀML GitHub Action
- dependency-free AML HTTP evaluation/verification service with OpenAPI contract
- reproducible 30-minute enterprise pilot

### Trust continuity

- expiring/revocable consent ledgers
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
- content-addressed AML bundles
- selective-disclosure commitments
- versioned `aml-wire/1` envelopes
- federated AML exchange
- causal execution graphs
- canonical JSON serialization
- golden protocol vectors
- wire replay protection

### Trust fabric

- delegated trust chains
- M-of-N threshold authorization
- append-only transparency logs
- bounded signed capability tokens
- revocation registries
- Proof-Carrying Interface™ manifests
- machine-verifiable conformance claims
- layered compatibility levels from Core through Governed

### Official AML verification

- machine-readable official-mark and authorization registries
- signed `aml-brand-authorization/1` credentials
- canonical ĀRU brand trust-root registry
- browser, CLI, HTTP, and GitHub Action verification paths
- a production ĀRU Ed25519 public trust root, published as public key + SHA-256 fingerprint only
- production private signing material intentionally kept outside GitHub

A cryptographically valid self-signed credential is **not** automatically an official ĀRU authorization. Official verification also requires an active, non-revoked signer fingerprint in the canonical ĀRU trust-root registry.

### Standards surface

- RFC process and RFCs 0001–0011
- protocol discovery and registry
- JSON Schemas
- compatibility/conformance levels
- independent second-runtime challenge
- explicit governance and standardization path
- dedicated threat model and key-custody guidance

## Try it

- Playground: https://aruintelligence.github.io/aml-core/playground.html
- View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html
- Official AML / licensing: https://aruintelligence.github.io/aml-core/official-aml.html
- Official authorization verifier: https://aruintelligence.github.io/aml-core/official-verify.html
- Enterprise pilot: `pilots/enterprise-30min/`
- HTTP service: `npm run serve`

## Verify the repository

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
npm run check:links
npm test
npm run benchmark
```

The dedicated AML Conformance workflow separately verifies the published conformance surface.

## Open-source and brand boundary

Covered software remains under the MIT License. Official ĀML™ / ĀRU™ branding, logos, compatibility branding, certification-style identity, endorsement, OEM/co-branding, and related brand rights are separate from the software license.

Technical conformance does not by itself imply official authorization, certification, endorsement, partnership, or trademark rights.

## Evidence boundary

ĀML improves inspectability, policy control, reproducibility, interoperability, and cryptographic integrity. It does not establish that current attention/restoration values objectively measure cognition or wellbeing; it does not make an AI's declared intent truthful; and accessibility policy experiments do not replace WCAG conformance or assistive-technology testing.

Cryptographic signatures establish integrity and key possession. They do not establish moral correctness or institutional trust by themselves.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**.
