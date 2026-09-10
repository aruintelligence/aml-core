# ĀML vs. HTML

## Not a replacement fight — a different layer

HTML answers a foundational browser question:

> **What should be represented and rendered?**

ĀML™ — ĀRU Meaning Language™ — explores a different question:

> **Why should this machine-generated interface be rendered, under which policy, and with what evidence?**

That distinction matters because AI-generated interfaces introduce decision-making that is not naturally expressed by markup alone.

## HTML remains essential

ĀML does not require teams to abandon HTML, CSS, JavaScript, React, Next.js, or existing browser infrastructure.

A useful mental model is:

```text
ĀML = meaning + policy + accountability decision layer
HTML = rendering and document/interface substrate
```

The two can coexist.

## Why markup alone is not enough for generated UI accountability

A rendered page can reveal structure and content while still leaving important questions unanswered:

- What purpose did the generating system declare?
- Which policy allowed this output?
- Was consent required?
- What privacy constraints applied?
- Did a semantic change occur between releases?
- Was a high-attention interface decision challenged or suppressed?
- Who or what had authority to generate the action?
- Can the decision be independently reproduced?

ĀML explores explicit machine-readable structures for those questions.

## The shortest demonstration

Open:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

The reference prototype applies the declared rule:

```text
render_allowed = restoration_value >= attention_cost
```

Change `restoration_value` from `1` to `5`. The decision changes. The result can be represented with a receipt that can be inspected and reproduced.

The scores are declared/model inputs in this prototype. They are not scientific claims that human attention or wellbeing has been objectively measured.

## Existing HTML can participate

ĀML includes narrow adoption bridges so existing markup can be evaluated without a ground-up rewrite.

### Custom-element bridge

```html
<aml-gate
  purpose="Create urgency"
  attention-cost="5"
  restoration-value="1">
  <button>Act now</button>
</aml-gate>
```

### DOM annotation bridge

```html
<div
  data-aml-purpose="Create urgency"
  data-aml-attention-cost="5"
  data-aml-restoration-value="1">
  Offer expires soon.
</div>
```

These bridges demonstrate adoption paths. They do not represent the full AML policy, trust, consent, privacy, accessibility, or provenance stack.

## A better comparison

The useful comparison is not "AML replaces HTML."

It is closer to:

**HTML renders the interface. ĀML can govern and explain the decision to render it.**

That makes AML relevant to AI-generated UI, agentic interfaces, adaptive interfaces, policy-aware rendering, semantic release verification, and accountable human-computer interaction.

## See also

- [AI Interface Firewall™](AI_INTERFACE_FIREWALL.md)
- [Generative UI Governance](GENERATIVE_UI_GOVERNANCE.md)
- [Why AI-generated UI needs a firewall](WHY_AI_UI_NEEDS_A_FIREWALL.md)
- [View Meaning™](VIEW_MEANING_EXPLAINER.md)
- [Meaning Gate™](MEANING_GATE_EXPLAINER.md)
- [Claims ledger](../CLAIMS.md)
- [Independent witness protocol](AML_WITNESS_PROTOCOL.md)

## Evidence boundary

ĀML is a working research prototype and open technology. It is not represented as a replacement for the web platform, a ratified global standard, or a universally adopted language.

Its strongest claim is narrower and testable: **machine-generated interfaces can carry more inspectable meaning, policy, provenance, and evidence than rendered markup alone provides.**
