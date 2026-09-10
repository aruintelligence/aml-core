# Discover ĀML™ — ĀRU Meaning Language™

ĀML™ is a meaning-native, policy-aware interface language and accountability layer for AI-generated and machine-generated interfaces.

Its central idea is simple:

> HTML describes what a browser should display. ĀML describes the declared meaning, purpose, policy, authority, and evidence behind what is allowed to reach a human interface.

ĀML is being developed as an open technical system around an **AI Interface Firewall™**: a layer that can inspect machine intent before rendering, apply explicit policy, record decisions, and produce evidence that can be independently examined.

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

## For enterprise teams

The repo includes an enterprise buyer brief, developer integration material, and a 30-minute pilot path designed to make evaluation concrete rather than theoretical.

Start with:

- `publications/ENTERPRISE_BUYER_BRIEF.md`
- `publications/DEVELOPER_INTEGRATION_BRIEF.md`
- `pilots/enterprise-30min/`
- `docs/TRY_AML_10_MINUTES.md`

## Search terms and research vocabulary

ĀML intersects with:

AI interface accountability, accountable AI UI, AI-generated interfaces, AI governance, machine-generated UI, interface policy enforcement, semantic UI, meaning-native interfaces, verifiable interfaces, AI provenance, policy-aware rendering, consent-aware interfaces, privacy-aware UI, accessibility-aware AI, AI audit receipts, AI interface firewall, explainable interfaces, trustworthy AI systems, human-centered AI, AI UX governance, semantic diffing, interface provenance, cryptographic receipts, AI safety tooling, AI compliance infrastructure, agentic UI governance, generative UI policy, machine intent, human attention, and verifiable AI interaction.

## Share the project

Repository: https://github.com/aruintelligence/aml-core

Live proof: https://aruintelligence.github.io/aml-core/proof.html

Playground: https://aruintelligence.github.io/aml-core/playground.html

View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html

Publications: https://github.com/aruintelligence/aml-core/blob/main/PUBLICATIONS.md

## Project identity

ĀML™ / ĀRU Meaning Language™ is developed by ĀRU Intelligence Inc.

Open-source code is governed by the repository license. Official branding, marks, compatibility identity, certification-style claims, endorsement, and commercial/OEM authorization are separate matters described in the repository's trademark and commercial documentation.
