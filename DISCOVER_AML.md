# Discover ĀML™ — ĀRU Meaning Language™

ĀML™ is a meaning-native, policy-aware interface language and accountability layer for AI-generated and machine-generated interfaces.

Its central idea is simple:

> HTML describes what a browser should display. ĀML describes the declared meaning, purpose, policy, authority, and evidence behind what is allowed to reach a human interface.

ĀML is being developed as an open technical system around an **AI Interface Firewall™**: a layer that can inspect machine intent before rendering, apply explicit policy, record decisions, and produce evidence that can be independently examined.

## Choose your path

Do not read the entire repository first. Start with the reason you came.

### I want the fastest proof

1. Open https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en
2. Change `restoration_value` from `1` to `5`.
3. Inspect the ALLOW/SUPPRESS decision and receipt.
4. Reproduce it locally with [`docs/TRY_AML_10_MINUTES.md`](docs/TRY_AML_10_MINUTES.md).

### I build AI agents or generative UI

- [ĀML for AI Agents](publications/AML_FOR_AI_AGENTS.md)
- [Generative UI Governance](publications/GENERATIVE_UI_GOVERNANCE.md)
- [AI Interface Firewall™](publications/AI_INTERFACE_FIREWALL.md)

Core question: **When an AI system can change the interface, how can the decision behind that interface become inspectable?**

### I am a developer

- [ĀML for Developers](publications/AML_FOR_DEVELOPERS.md)
- [ĀML vs. HTML](publications/AML_VS_HTML.md)
- [Evaluate ĀML in 15 minutes](publications/EVALUATE_AML_IN_15_MINUTES.md)

Core question: **Can I add meaning, policy, and evidence without rebuilding my frontend stack?**

### I evaluate enterprise AI

- [ĀML for Enterprise Evaluation](publications/AML_FOR_ENTERPRISE.md)
- [Security threat model](SECURITY_THREAT_MODEL.md)
- [Claims ledger](CLAIMS.md)
- [Deploy ĀML without breaking production](publications/DEPLOY_AML_WITHOUT_BREAKING_PRODUCTION.md)

Core question: **Can generated-interface decisions be inspected, challenged, reproduced, and governed before production enforcement?**

### I work in research or standards

- [ĀML for Standards and Research Evaluation](publications/AML_STANDARDS_AND_RESEARCH.md)
- [Public Witness Protocol](publications/AML_WITNESS_PROTOCOL.md)
- [Claims ledger](CLAIMS.md)
- [Standardization path](STANDARDIZATION.md)

Core question: **Are the abstractions, schemas, semantics, conformance surfaces, and verifier model precise enough to test or reimplement independently?**

### I am skeptical

Good. Start here:

- [Public Witness Protocol](publications/AML_WITNESS_PROTOCOL.md)
- [A critic's guide to ĀML](publications/CRITICS_GUIDE.md)
- [Proof Map](publications/PROOF_MAP.md)
- [Claims ledger](CLAIMS.md)

Do not endorse ĀML first. Try to break a claim and publish the reproduction.

## Why this matters now

AI systems increasingly generate, personalize, rank, recommend, persuade, and render interfaces dynamically. Traditional UI stacks are excellent at presentation, but they do not inherently provide a standardized way to answer questions such as:

- Why was this element shown?
- What declared purpose justified it?
- Which policy allowed or suppressed it?
- What consent, privacy, accessibility, and attention constraints were considered?
- Who or what had authority to make the decision?
- Can the decision be reproduced or independently verified later?

ĀML explores a technical answer to that accountability gap.

## What exists today

The public reference implementation includes:

- lexer, parser, AST, and Abstract Meaning Tree
- semantic and policy analysis
- deterministic render decisions
- consent, privacy, accessibility, and attention-aware policy surfaces
- execution receipts and cryptographic verification
- signed policy and authorization artifacts
- provenance and audit structures
- protocol, schema, RFC, conformance, and interoperability work
- a browser playground and live proof
- View Meaning™ inspection concepts and tools
- Meaning Gate™ CI integration
- browser bridges for existing HTML and web applications
- enterprise pilot and adoption materials

This is a working research prototype and evolving specification—not a claim that ĀML is already an Internet standard or that its current human-impact scores are objective scientific measurements.

## Fastest way to understand ĀML

1. Open the live proof: https://aruintelligence.github.io/aml-core/proof.html
2. Change the declared attention/restoration inputs.
3. Observe the deterministic ALLOW/SUPPRESS decision.
4. Open the playground: https://aruintelligence.github.io/aml-core/playground.html
5. Read `publications/START_HERE.md` and `publications/AML_IN_ONE_PAGE.md`.
6. Inspect `README.md`, `ARCHITECTURE.md`, `API.md`, `VERIFY.md`, and the RFC directory.

## For AI developers

ĀML can sit between model/app intent and the rendered interface. It does not require replacing HTML, React, Next.js, or existing frontend infrastructure.

Potential use cases include:

- accountable AI-generated UI
- policy enforcement before rendering
- semantic review of model-generated interface changes
- provenance for dynamic experiences
- explicit consent/privacy checks
- audit receipts for high-stakes workflows
- organization-specific interface policy
- independent inspection of why a machine-facing decision reached a user

## For security, privacy, and governance teams

ĀML treats interface output as something that can carry inspectable policy and evidence. Relevant surfaces include:

- explicit policy evaluation
- signed receipts
- replay protection
- authorization and revocation
- trust delegation
- provenance graphs
- transparency structures
- independent verification
- policy and semantic diffs

## For researchers and standards communities

The project publishes specifications, RFCs, schemas, canonicalization rules, protocol vectors, conformance fixtures, and an explicit path toward independent implementations.

Useful starting points:

- `STANDARDIZATION.md`
- `ECOSYSTEM.md`
- `rfcs/README.md`
- `protocol/`
- `schemas/`
- `CITATION.cff`
- `publications/AML_STANDARDS_AND_RESEARCH.md`

## For enterprise teams

The repo includes an enterprise buyer brief, developer integration material, and a 30-minute pilot path designed to make evaluation concrete rather than theoretical.

Start with:

- `publications/AML_FOR_ENTERPRISE.md`
- `publications/ENTERPRISE_BUYER_BRIEF.md`
- `publications/DEVELOPER_INTEGRATION_BRIEF.md`
- `pilots/enterprise-30min/`
- `docs/TRY_AML_10_MINUTES.md`

## Search terms and research vocabulary

ĀML intersects with:

AI interface accountability, accountable AI UI, AI-generated interfaces, AI governance, machine-generated UI, interface policy enforcement, semantic UI, meaning-native interfaces, verifiable interfaces, AI provenance, policy-aware rendering, consent-aware interfaces, privacy-aware UI, accessibility-aware AI, AI audit receipts, AI interface firewall, explainable interfaces, trustworthy AI systems, human-centered AI, AI UX governance, semantic diffing, interface provenance, cryptographic receipts, AI safety tooling, AI compliance infrastructure, agentic UI governance, generative UI policy, generative UI governance, machine intent, human attention, verifiable AI interaction, AI agent interface governance, and independently verifiable generated interfaces.

These are descriptive discovery terms and do not imply standards-body adoption.

## Share the project

Repository: https://github.com/aruintelligence/aml-core

Live proof: https://aruintelligence.github.io/aml-core/proof.html

Playground: https://aruintelligence.github.io/aml-core/playground.html

View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html

Publications: https://github.com/aruintelligence/aml-core/blob/main/PUBLICATIONS.md

Public witness protocol: https://github.com/aruintelligence/aml-core/blob/main/publications/AML_WITNESS_PROTOCOL.md

## Project identity

ĀML™ / ĀRU Meaning Language™ is developed by ĀRU Intelligence Inc.

Open-source code is governed by the repository license. Official branding, marks, compatibility identity, certification-style claims, endorsement, and commercial/OEM authorization are separate matters described in the repository's trademark and commercial documentation.

## The challenge

**Run it. Inspect it. Reproduce it. Break it. Publish what you find.**
