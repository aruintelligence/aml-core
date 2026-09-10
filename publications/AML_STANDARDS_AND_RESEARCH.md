# ĀML for Standards and Research Evaluation

## A falsifiable interface-accountability proposal

ĀML™ — ĀRU Meaning Language™ — is a working research prototype exploring how machine-generated interfaces can expose structured meaning, policy context, authority, provenance, and evidence around render decisions.

It is **not** presented here as a ratified global standard. The useful question for researchers and standards participants is whether the underlying problems, abstractions, schemas, conformance surfaces, and verification model are worth testing, criticizing, refining, or reimplementing independently.

## Research question

As AI systems generate or adapt interfaces dynamically, conventional markup can describe the resulting document or UI while leaving the decision process itself comparatively opaque.

A standards-oriented investigation can ask:

> Can interface intent, governing policy, authority, decision outcome, and evidence be represented in a portable form that another implementation can inspect or verify?

ĀML is one concrete proposal for exploring that question.

## What should be examined independently

Researchers and implementers can evaluate:

- language and schema design
- canonicalization behavior
- deterministic decision semantics
- semantic diffs
- policy representation
- consent/privacy/accessibility conditions
- capability and authority models
- execution receipts
- provenance structures
- cryptographic evidence experiments
- conformance fixtures and golden vectors
- interoperability assumptions
- versioning and compatibility levels
- governance and trademark separation

## The minimum reproducibility test

Start with the public proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

Then reproduce the behavior locally with [`TRY_AML_10_MINUTES.md`](../docs/TRY_AML_10_MINUTES.md).

The reference demonstration exposes a simple declared rule:

```text
render_allowed = restoration_value >= attention_cost
```

The declared values in this proof are model inputs, not validated scientific measurements of human cognition or wellbeing.

## What would strengthen the work

The project becomes more credible when independent parties can:

1. implement a compatible verifier from public specifications;
2. reproduce canonicalization vectors;
3. identify ambiguity in schemas or semantics;
4. construct counterexamples;
5. publish interoperability failures;
6. test threat-model assumptions;
7. compare AML concepts with existing policy, provenance, security, accessibility, and web standards;
8. propose narrower or better abstractions;
9. distinguish normative specification from experimental implementation;
10. publish results without requiring permission from ĀRU.

## Existing accountability surfaces

- [Public Witness Protocol](AML_WITNESS_PROTOCOL.md)
- [Claims ledger](../CLAIMS.md)
- [Security threat model](../SECURITY_THREAT_MODEL.md)
- [AI Interface Firewall™](AI_INTERFACE_FIREWALL.md)
- [Generative UI Governance](GENERATIVE_UI_GOVERNANCE.md)
- [ĀML vs. HTML](AML_VS_HTML.md)

The repository also includes RFC-oriented material, schemas, conformance fixtures, compatibility levels, and independent-verifier work intended to make the proposal inspectable rather than purely rhetorical.

## Terminology and status

Terms such as **AI Interface Firewall™, View Meaning™, Meaning Gate™, generative UI governance, interface provenance, policy-aware rendering, and semantic interface accountability** describe concepts explored by this project. Their use does not imply adoption by a standards organization.

Software licensing and official ĀRU/AML marks are separate concerns. Technical compatibility does not itself grant trademark authorization or endorsement.

## Research invitation

The best outcome is not uncritical agreement. It is sharper definitions, independent implementations, reproducible failures, stronger conformance, and evidence that survives scrutiny.

**Treat ĀML as a proposal you can test—not a conclusion you are asked to accept.**
