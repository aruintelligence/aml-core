# Adopt ĀML™ — from first proof to controlled evaluation

ĀML™ — ĀRU Meaning Language™ — is a working research prototype for meaning-native, policy-aware, accountable AI interfaces. This page is the canonical adoption spine for teams that want to move from curiosity to a controlled technical evaluation without confusing prototype evidence with production readiness.

## The adoption rule

**Do not begin with a platform rewrite. Begin with a falsifiable interface decision.**

ĀML is designed to sit between machine/app intent and human-facing output. Existing HTML, React, Next.js, APIs, and browser infrastructure can remain in place while teams evaluate whether explicit meaning, policy, authority, provenance, and receipts improve accountability.

## Stage 0 — understand the claim

Start here:

- [What is ĀML?](what-is-aml.html)
- [Discover ĀML](DISCOVER_AML.md)
- [ĀML in one page](publications/AML_IN_ONE_PAGE.md)
- [ĀML vs. HTML](publications/AML_VS_HTML.md)
- [AI Interface Firewall™](publications/AI_INTERFACE_FIREWALL.md)

The central distinction is:

> HTML renders the interface. ĀML can govern and explain the decision to render it.

## Stage 1 — reproduce one decision

Open the live proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

Then:

1. record the initial decision;
2. change `restoration_value` from `1` to `5`;
3. record the new decision;
4. inspect the receipt/evidence surface;
5. reproduce locally using [TRY_AML_10_MINUTES](docs/TRY_AML_10_MINUTES.md).

Prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

The values are declared/model inputs. They are not objective scientific measurements of human cognition, wellbeing, manipulation, or harm.

## Stage 2 — evaluate the software contract

Before discussing deployment, test whether the project behaves as documented.

Use:

- [Claims ledger](CLAIMS.md)
- [Proof map](publications/PROOF_MAP.md)
- [Verify AML without trusting AML](VERIFY.md)
- [Public challenge map](CHALLENGES.md)
- [Public witness protocol](publications/AML_WITNESS_PROTOCOL.md)
- [Conformance surface](conformance/)

Record disagreements. A useful evaluation can conclude PASS, FAIL, or MIXED.

## Stage 3 — integrate narrowly

Do not start with high-risk enforcement.

Possible narrow entry points include:

- `<aml-gate>` around one existing interface component;
- `data-aml-*` annotations on selected existing DOM elements;
- a backend/API evaluation call before rendering;
- semantic review in CI using Meaning Gate™;
- View Meaning™ for inspection;
- a non-production test harness around an AI-generated interface.

Reference paths:

- [Developer integration brief](publications/DEVELOPER_INTEGRATION_BRIEF.md)
- [Out-of-the-box adoption](docs/OUT_OF_THE_BOX.md)
- [HTML bridge](docs/HTML_BRIDGE.md)
- [AML Gate element](docs/AML_GATE_ELEMENT.md)
- [HTTP contract](protocol/aml-http.openapi.yaml)

## Stage 4 — run in shadow mode

A serious evaluator should first observe AML decisions without allowing AML to change production behavior.

Recommended shadow-mode evidence:

- input snapshot;
- declared purpose;
- policy/profile used;
- AML decision;
- production decision;
- receipt/hash;
- disagreement rate;
- false-positive review;
- false-negative review;
- latency and operational overhead;
- unresolved ambiguity.

Do not call a shadow-mode result “production validation.” It is evaluation evidence.

## Stage 5 — canary a bounded surface

If shadow evidence is acceptable, move only a low-risk, reversible subset into canary enforcement.

Define before starting:

- exact surface in scope;
- rollback trigger;
- owner;
- observability;
- policy version;
- receipt retention policy;
- latency budget;
- failure behavior;
- security review;
- user-impact review.

See [Deploy ĀML without breaking production](publications/DEPLOY_AML_WITHOUT_BREAKING_PRODUCTION.md).

## Stage 6 — independent verification

Before a high-confidence adoption claim, ask someone outside the implementation path to reproduce evidence.

Useful routes:

- [Independent implementation challenge](https://github.com/aruintelligence/aml-core/issues/1)
- [Third-runtime witness challenge](https://github.com/aruintelligence/aml-core/issues/15)
- [Independent semantic-release verifier challenge](https://github.com/aruintelligence/aml-core/issues/56)
- [General public verification call](https://github.com/aruintelligence/aml-core/issues/88)

An independent result may support or contradict the reference implementation. Both are valuable.

## Stage 7 — production-readiness decision

A production decision is broader than “the demo worked.”

Review at minimum:

- authentication and authorization;
- TLS and network controls;
- secret/key management;
- logging and audit retention;
- availability/failover;
- rate limiting and abuse resistance;
- rollback and incident response;
- dependency risk;
- browser/security boundaries where applicable;
- legal/privacy requirements applicable to the deployment;
- policy ownership and change control;
- evidence retention and verification;
- performance and cost;
- false-positive/false-negative tolerance;
- accessibility impact;
- human override and escalation.

Use [Security Evaluation Checklist](docs/SECURITY_EVALUATION_CHECKLIST.md) as a starting point.

## Stage 8 — publish what was actually learned

The strongest adoption evidence is reproducible and scoped.

A useful public report states:

- which AML version/commit was tested;
- what surface was evaluated;
- exact policy/configuration;
- expected behavior;
- observed behavior;
- independent verification status;
- failures and limitations;
- whether the result was prototype, shadow, canary, or production evidence.

Do not turn one successful pilot into a universal adoption claim.

## Machine-readable adoption path

Automated evaluators can consume [`adoption-path.json`](adoption-path.json).

## Product truth

ĀML is not represented here as:

- a ratified global standard;
- universally adopted infrastructure;
- scientifically validated measurement of cognition or wellbeing;
- a complete production security stack;
- a guarantee of safe, ethical, legal, or compliant interfaces.

It is a working technical system with public code, specifications, proofs, receipts, verification surfaces, and falsifiable claims.

**Find it. Run it. Challenge it. Integrate it narrowly. Measure it. Verify it independently. Expand only when the evidence earns the next step.**
