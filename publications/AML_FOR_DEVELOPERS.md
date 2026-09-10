# ĀML for Developers

## Add inspectable meaning and policy without rebuilding the web stack

ĀML™ — ĀRU Meaning Language™ — is a working research prototype for developers who want machine-generated interfaces to expose more than pixels and DOM structure.

The practical idea is straightforward:

```text
application / model intent
        ↓
ĀML meaning + policy evaluation
        ↓
render decision + explanation + receipt
        ↓
your existing HTML / React / UI
```

ĀML does not require replacing HTML, CSS, JavaScript, React, Next.js, or the browser.

## Start with a reproducible test

Open the public proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

Then follow [`TRY_AML_10_MINUTES.md`](../docs/TRY_AML_10_MINUTES.md) and compare your local result.

The reference prototype uses a deliberately visible rule:

```text
render_allowed = restoration_value >= attention_cost
```

The purpose of the demo is not to claim that these numbers objectively measure human cognition. It is to make the decision path explicit, reproducible, and inspectable.

## What developers can evaluate

The repository exposes concrete surfaces for:

- parsing and structured meaning
- policy evaluation
- semantic diffs
- consent/privacy/accessibility conditions
- deterministic execution receipts
- signed and hashed evidence experiments
- provenance
- conformance fixtures
- browser integration bridges
- HTTP integration
- GitHub workflow gating
- independent verifier paths

## Use existing markup

A narrow bridge can wrap existing content:

```html
<aml-gate
  purpose="Create urgency"
  attention-cost="5"
  restoration-value="1">
  <button>Act now</button>
</aml-gate>
```

Or existing DOM can carry `data-aml-*` annotations where appropriate.

These bridges are adoption surfaces, not the entire AML model.

## A developer checklist

Before accepting any AML claim, ask:

1. Can I reproduce the example locally?
2. Is the rule or policy visible?
3. Is the decision deterministic for the same declared inputs?
4. Can I inspect the receipt?
5. Can I detect semantic changes between examples or releases?
6. Can I test a failure case?
7. Can I verify evidence outside the rendering page?
8. Does the claims ledger classify the claim honestly?

## Useful entry points

- [AI Interface Firewall™](AI_INTERFACE_FIREWALL.md)
- [Generative UI Governance](GENERATIVE_UI_GOVERNANCE.md)
- [ĀML vs. HTML](AML_VS_HTML.md)
- [Public Witness Protocol](AML_WITNESS_PROTOCOL.md)
- [Claims ledger](../CLAIMS.md)
- [Security threat model](../SECURITY_THREAT_MODEL.md)

## Search language

**AML developer, AI interface accountability, generative UI developer tools, semantic UI policy, policy-aware rendering, AI interface receipts, generated UI provenance, AI interface firewall, machine-verifiable UI, View Meaning, Meaning Gate, accountable AI frontend.**

These are descriptive discovery terms, not claims of external adoption.

## The developer invitation

Clone it. Run it. Test a known case. Construct a hostile case. Compare the receipt. File a reproducible disagreement.

**A new interface layer earns credibility when developers can independently prove where it works and where it fails.**
