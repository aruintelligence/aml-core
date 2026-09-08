# Why ĀML™ Now

AI systems are increasingly generating interfaces, selecting content, requesting consent, collecting data, prioritizing attention, and adapting experiences in real time.

The browser can render those outputs. The harder question is whether the system can explain **why** an interface element exists, which policy allowed it, what user context mattered, what authority the agent had, and what evidence remains afterward.

ĀML™ — ĀRU Meaning Language™ — is an experimental accountability layer for that gap.

## The problem

Traditional interface stacks are excellent at describing structure, style, events, and application state.

They usually do not require a machine-generated interface to declare:

- purpose
- attention cost
- restoration value
- consent dependency
- privacy behavior
- accessibility context
- policy identity
- policy disagreement
- authority scope
- causal lineage
- verifiable post-execution evidence

As AI becomes a more direct producer of human-facing software, those missing properties become operationally important.

## The AML proposition

> **HTML tells the browser what to display. ĀML tells the system why it deserves to be displayed.**

AML does not need to replace HTML or React to be useful.

It can operate before rendering:

```text
AI/app intent
→ AML meaning model
→ policy/accessibility/consent/privacy evaluation
→ render decision
→ existing UI output
→ execution receipt
→ independent verification
```

That makes AML usable as an **AI Interface Firewall™** rather than requiring a complete rewrite of the web.

## What is different

### 1. Meaning is inspectable

AML builds an Abstract Meaning Tree in addition to ordinary syntax structures.

Semantic diffs can show changes such as:

- purpose changed
- personal-data collection introduced
- consent requirement removed
- attention cost increased
- accessibility declaration changed

That is a different question from whether a source line changed.

### 2. Policy disagreement is evidence

AML can evaluate the same meaning under multiple policies and preserve disagreement rather than collapsing everything into one unexplained Boolean.

### 3. Execution produces receipts

An accountable execution can bind intent, generated AML, policy decisions, runtime context, final output, audit state, and other artifacts into a verifiable receipt.

### 4. Trust can travel across systems

The interoperability layer experiments with:

- capability negotiation
- portable policy passports
- content-addressed bundles
- wire envelopes
- causal execution graphs
- bounded capability tokens
- replay resistance
- trust delegation
- threshold authorization
- revocation

### 5. Interfaces can carry proof

Proof-Carrying Interface™ manifests can cryptographically bind rendered output to the accountability artifacts intended to justify it.

### 6. Users can inspect meaning

**View Meaning™** explores a user/developer experience analogous to View Source, but for purpose, policy, consent/privacy/accessibility context, render outcomes, and receipt integrity.

## Why this matters for AI agents

An AI agent may be able to generate valid HTML, React, or application state while still exceeding its authority, violating a user preference, changing privacy behavior, or producing an interface whose rationale disappears after rendering.

AML is exploring a model where the agent's proposed action is only one input.

The actual execution can additionally depend on:

- user-owned policy
- organization policy
- consent state
- accessibility preferences
- privacy constraints
- attention budget
- delegated authority
- runtime compatibility

The result can then produce evidence that survives the interaction.

## Why this matters for developers

AML is intentionally being built so adoption can start incrementally:

- zero-install browser demo
- plain JavaScript starter
- React adapter
- Next.js starter
- GitHub Meaning Gate™
- dependency-free HTTP service
- enterprise pilot kit
- browser inspector

A team does not need to rewrite its application in `.aml` to experiment with the accountability model.

## Why this matters for standards work

A standard cannot depend on one repository's implementation details.

That is why AML publishes:

- RFCs
- schemas
- conformance fixtures
- compatibility levels
- protocol discovery
- registries
- canonical serialization rules
- golden protocol vectors
- an independent second-runtime challenge

The reference implementation should be challengeable by another implementation.

## Why this matters for security

Accountability artifacts are only useful if mutation, replay, forged authority, revoked keys, or self-signed claims can be detected.

The AML trust surface therefore includes experiments around:

- Ed25519 signatures
- SHA-256 content addressing
- hash-chained logs
- Merkle inclusion proofs
- replay guards
- capability scopes
- revocation registries
- trusted-key registries

Cryptography does not prove that a policy is morally correct. It can make specific integrity and authorization claims testable.

## Open technology and official identity

Covered source code remains available under the repository's MIT License.

Official AML/ĀRU branding, endorsement, compatibility identity, and other reserved brand rights are separate from the software license.

Technical conformance can be tested independently. Official authorization requires a separate basis and, where used, can be represented by a signed AML authorization credential verified against the canonical ĀRU trust-root registry.

## What AML does not claim

AML does not currently establish that:

- attention scores objectively measure cognition
- restoration scores objectively measure wellbeing
- one policy model is universally ethical
- accessibility policies replace WCAG conformance testing
- a signature proves institutional trustworthiness
- an AI's declared intent is necessarily truthful

Those boundaries are important to the credibility of the project.

## Try it

- Playground: https://aruintelligence.github.io/aml-core/playground.html
- View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html
- Official AML verifier: https://aruintelligence.github.io/aml-core/official-verify.html
- Enterprise pilot: `pilots/enterprise-30min/`
- Full API: `API.md`
- Ecosystem map: `ECOSYSTEM.md`
- Roadmap: `ROADMAP.md`
- v1.4 release-candidate notes: `RELEASE_NOTES_1.4.0_RC1.md`

## The question AML is trying to make practical

> **When AI generates an interface, can the system prove what it meant, what authority it had, which policies governed it, and why the human saw the result?**

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**.
