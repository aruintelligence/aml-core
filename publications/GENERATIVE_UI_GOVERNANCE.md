# Generative UI Governance

## What governs an interface when the interface itself is generated?

Generative UI changes a basic assumption of software delivery. Instead of a team designing every screen in advance, an AI system may generate or assemble parts of the human interface at runtime.

That raises a governance question:

> **What evaluates the meaning of generated output before a human sees it?**

ĀML™ — ĀRU Meaning Language™ — is a working research prototype for making generated interface intent, policy, authority, and evidence inspectable.

## The governance gap

A conventional UI pipeline may govern source code, dependencies, deployment, authentication, and data access while leaving a generated interface decision comparatively opaque.

A generated interface can potentially vary by:

- model output
- user context
- policy profile
- session state
- personalization
- consent state
- accessibility needs
- organizational rules
- tool authority
- release version

The pixels alone may not explain why the system chose them.

## A meaning-first control plane

ĀML explores a control plane that can sit before rendering:

```text
machine intent → structured meaning → policy evaluation → render decision → receipt
```

The resulting evidence can make it possible to inspect declared purpose, policy decisions, provenance, consent/privacy context, accessibility analysis, and render outcome.

## Governance should be testable

A useful governance mechanism should not require trusting the vendor's description of itself.

ĀML therefore publishes:

- deterministic proof surfaces
- execution receipts
- claims ledgers
- conformance fixtures
- protocol schemas
- golden vectors
- independent verification paths
- release coherence checks
- cryptographic trust and provenance experiments

Start with the live proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

Then reproduce it locally using [TRY_AML_10_MINUTES.md](../docs/TRY_AML_10_MINUTES.md).

## Governance without a frontend rewrite

The adoption path does not require replacing HTML or React.

ĀML includes narrow compatibility bridges for existing frontend stacks, including a custom element and `data-aml-*` DOM annotations. These are intentionally limited surfaces, not claims that the entire governance model is contained in three attributes.

## Questions an enterprise evaluator should ask

1. Can the system disclose the declared purpose of generated interface output?
2. Can policy be evaluated before rendering rather than only audited afterward?
3. Can decisions be reproduced deterministically?
4. Can a third party verify evidence independently?
5. Can semantic changes be detected across releases?
6. Can consent, privacy, accessibility, and authority boundaries participate in the decision?
7. Can an organization introduce the control in shadow or canary mode before enforcement?
8. Are product claims machine-readable and checked against repository evidence?

## Related terms

This work overlaps with discussions around **generative UI governance, AI interface governance, AI UX safety, policy-aware rendering, AI product governance, generated interface auditing, semantic release controls, interface provenance, accountable AI interfaces, and AI Interface Firewall™**.

No standards-body adoption is implied by this terminology.

## Evaluate rather than endorse

ĀML does not ask evaluators to assume its thesis is correct. The repository deliberately exposes falsifiable surfaces.

- [Claims ledger](../CLAIMS.md)
- [Critic's guide](CRITICS_GUIDE.md)
- [Evaluate AML in 15 minutes](EVALUATE_AML_IN_15_MINUTES.md)
- [Independent witness protocol](../WITNESS_AML.md)
- [Security threat model](../SECURITY_THREAT_MODEL.md)

**Generated interfaces need governance that can itself be inspected. ĀML is one concrete attempt to build it.**
