# AI Interface Firewall™

## A decision boundary between machine intent and human-facing output

AI systems increasingly generate, select, rank, personalize, or assemble interfaces dynamically. That creates a new control problem: the system may know **what** it wants to show without exposing **why**, under which policy, with which authority, or with what evidence.

ĀML™ — ĀRU Meaning Language™ — explores an **AI Interface Firewall™**: a layer placed between AI/app intent and rendered UI so meaning and policy can be inspected before output reaches a person.

The core idea is simple:

```text
AI / app intent
      ↓
ĀML meaning + policy layer
      ↓
ALLOW / SUPPRESS / explain / receipt
      ↓
HTML / React / existing UI
```

This does not require replacing HTML, React, Next.js, or the browser. HTML remains the rendering substrate. ĀML adds a machine-readable accountability boundary around the decision to render.

## Why this category exists

Traditional frontend systems are excellent at rendering interfaces. They are much weaker at making generated interface decisions independently inspectable.

An accountable AI interface may need to expose:

- declared purpose
- policy profile
- attention and restoration inputs
- consent and privacy context
- accessibility analysis
- authority and capability boundaries
- allow/suppress rationale
- provenance
- deterministic execution receipts
- cryptographic verification

ĀML is a working research prototype for that problem.

## Try the concept in one minute

Open the live proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

The reference prototype begins with a declared rule:

```text
render_allowed = restoration_value >= attention_cost
```

Change `restoration_value` from `1` to `5` and inspect the decision and receipt.

The scores in this prototype are declared/model inputs. They are not claimed objective measurements of cognition, wellbeing, manipulation, or harm.

## Use it without replacing your frontend

### Wrap existing content

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-gate.js"></script>

<aml-gate purpose="Create urgency" attention-cost="5" restoration-value="1">
  <button>Act now</button>
</aml-gate>
```

### Or annotate the existing DOM

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-dom-gate.js"></script>

<div
  data-aml-purpose="Create urgency"
  data-aml-attention-cost="5"
  data-aml-restoration-value="1">
  Offer expires soon.
</div>
```

## What makes a firewall different from a style layer

The goal is not prettier output. The goal is a **decision boundary**.

A useful interface firewall can answer questions such as:

- What did the generating system claim it was trying to do?
- Which policy evaluated that intent?
- Why was this interface allowed or suppressed?
- Did the meaning change between two releases even if the pixels barely changed?
- Can another party reproduce the decision?
- Can a verifier inspect the evidence without trusting the original page?

## Related AML surfaces

- [View Meaning™](VIEW_MEANING_EXPLAINER.md)
- [Meaning Gate™](MEANING_GATE_EXPLAINER.md)
- [Receipt anatomy](RECEIPT_ANATOMY.md)
- [Why AI-generated UI needs a firewall](WHY_AI_UI_NEEDS_A_FIREWALL.md)
- [Deploy ĀML without breaking production](DEPLOY_AML_WITHOUT_BREAKING_PRODUCTION.md)
- [Evaluate ĀML in 15 minutes](EVALUATE_AML_IN_15_MINUTES.md)
- [Independent witness protocol](../WITNESS_AML.md)
- [Claims ledger](../CLAIMS.md)

## Search language for this problem

The category overlaps with terms such as:

**AI interface accountability, generative UI governance, generated UI safety, AI interface policy, semantic interface governance, machine-generated UI auditing, verifiable generated interfaces, interface provenance, accountable AI UX, policy-aware rendering, AI UI firewall, AI interface firewall, View Meaning, Meaning Gate, and ĀRU Meaning Language.**

These terms are descriptive discovery language, not claims that a standards body has adopted the terminology.

## Evidence boundary

ĀML is open technology under the repository's software license and is still a research prototype. It is not represented here as a ratified global standard, universally adopted technology, or independently validated scientific measure of human attention or wellbeing.

The strongest way to evaluate it is not to accept the category claim. It is to reproduce the behavior, inspect the receipts, verify the published claims, and report disagreement publicly.

**Do not trust the pitch. Test the boundary.**
