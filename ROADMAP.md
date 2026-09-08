# ĀML™ Development Roadmap

ĀML™ is a working research prototype for meaning-native, policy-aware, accountable AI interfaces and cross-system trust.

## Current stable release — v1.3.0

Published release: [v1.3.0](https://github.com/aruintelligence/aml-core/releases/tag/v1.3.0)

Stable v1.3 introduced:

- signed policy packs
- semantic diffs
- policy diffs
- runtime audit streams
- accessibility-aware policies
- cumulative attention accounting
- execution receipts and signed attestations
- pluggable policy profiles
- deterministic machine intent → AML generation
- browser playground, CLI, LSP, VS Code language support, and conformance tooling

## Main branch — v1.4 release-candidate territory

Main now contains a much broader architecture than the v1.3 release. The current v1.4 release-candidate surface includes:

### Mainstream adoption

- AI Interface Firewall™
- View Meaning™ browser inspector
- View Meaning browser-extension prototype
- React-compatible accountable UI adapter
- plain-JavaScript, React, and Next.js starter kits
- Meaning Gate™ GitHub Action
- Verify Official ĀML GitHub Action
- dependency-free HTTP evaluation/verification service
- 30-minute enterprise pilot kit

### Trust continuity

- expiring and revocable consent ledgers
- policy consensus with explicit dissent
- semantic risk classification
- policy matrices
- signed audit checkpoints
- attention-ledger integrity verification
- receipt Merkle batching
- execution provenance graphs

### Cross-system interoperability

- capability negotiation
- portable policy passports
- content-addressed AML bundles
- selective-disclosure commitments
- versioned AML wire envelopes
- federated exchange
- causal execution graphs
- canonical JSON
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
- layered conformance from Core through Governed

### Official AML verification

- machine-readable official-mark registry
- signed brand-authorization credentials
- canonical ĀRU brand trust-root registry
- browser, CLI, HTTP, and GitHub Action verification
- first production ĀRU Ed25519 public trust root published by fingerprint/public key only
- private signing material kept outside GitHub

### Standards surface

- RFC process
- protocol discovery
- versioned registries
- schemas
- conformance levels
- conformance vectors
- explicit governance and standardization path
- independent second-runtime challenge

## Immediate priorities — next 30 days

### 1. Independent implementation

A second implementation that does not import `aml-core` should reproduce canonical serialization, wire envelopes, conformance vectors, and receipt verification. Any divergence becomes a specification bug to fix.

### 2. Package distribution

Publish a verified registry distribution once package metadata, release versioning, and distribution credentials can be advanced through the approved release path.

### 3. Security review

Invite independent review of:

- receipt integrity
- signed policy packs
- capability tokens
- replay resistance
- trust delegation
- threshold authorization
- revocation
- official-brand trust-root verification

### 4. Browser extension hardening

Move View Meaning™ from prototype toward a reviewable store package while preserving minimal permissions and local verification.

### 5. Enterprise pilots

Get external teams to run the 30-minute pilot against real AI-generated UI flows and report integration friction, policy ambiguity, and missing evidence.

## 30–90 day adoption goals

- verified package distribution
- real React/Next integration examples
- second-runtime interoperability result
- independent security review
- external accessibility review
- public benchmark corpus
- enterprise pilot feedback
- browser-extension beta
- broader standards and research outreach
- clearer spec/reference-implementation separation

## v2 research direction

The long-term research question remains whether the Abstract Meaning Tree can become an executable semantic substrate rather than only a compilation intermediate.

Potential directions:

- executable AMT graph traversal
- semantic-first runtime scheduling
- multi-agent authority negotiation
- user-controlled policy runtimes
- semantic continuity across sessions and devices
- accountability evidence that travels with rendered output
- cross-organization trust federation
- privacy-preserving policy disclosure where technically justified

## Evidence boundary

Roadmap items are research and engineering targets, not guarantees. Current ĀML policies do not establish scientifically validated universal measures of ethics, attention, restoration, privacy, accessibility, or wellbeing.

The goal is to make assumptions and decisions **explicit, testable, replaceable, reproducible, interoperable, and attestable**.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
