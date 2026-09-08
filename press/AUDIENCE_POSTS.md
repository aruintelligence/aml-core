# ĀML Audience Posts

## Designer post — dark patterns

**Status: DRAFT**

Dark patterns are often reviewed after they already exist as screenshots.

ĀML experiments with moving some of that review earlier by making an element declare purpose, attention cost, and restoration value before it renders.

A countdown-pressure fixture can declare:

```text
attention_cost: 5
restoration_value: 1
```

Under the prototype baseline, it is suppressed.

This is not a universal definition of harm. It is an inspectable policy decision that can be reviewed, changed, reproduced, and challenged.

Try it: https://aruintelligence.github.io/aml-core/playground.html

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

---

## Privacy-engineer post — receipts

**Status: DRAFT**

A consent banner tells you what the interface asked. A runtime receipt can tell you what a particular execution says it evaluated.

ĀML receipts can bind declared purpose, consent/privacy context, policy decisions, output hashes, and verification data.

That does **not** prove legal compliance or truthful intent. It creates an artifact that can be inspected later instead of relying only on screenshots and logs scattered across systems.

View Meaning: https://aruintelligence.github.io/aml-core/view-meaning.html

I want privacy engineers to attack the gaps: what is missing, what is misleading, and what should never be claimed from a receipt?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

---

## AI-product post — generated UI slop

**Status: DRAFT**

AI can generate 100 interface variants before a team finishes reviewing one.

The scaling problem is not only generation. It is reviewability.

ĀML is a prototype interface firewall that makes generated UI carry declared purpose and policy-relevant metadata into an inspectable decision and receipt.

It can sit in front of existing UI rather than requiring a new browser.

Repo: https://github.com/aruintelligence/aml-core

If this is useful, the test is simple: can a product engineer add it to a real generated-UI path without hating the integration?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
