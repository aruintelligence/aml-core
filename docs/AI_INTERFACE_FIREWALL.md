# ĀML™ AI Interface Firewall

The **ĀML AI Interface Firewall** is the mainstream integration surface for ĀML: AI or application code proposes an interface intent, and ĀML evaluates that intent before it reaches the user.

```text
AI / app intent
   ↓
ĀML Interface Firewall
   ├─ meaning + policy evaluation
   ├─ privacy / consent checks
   ├─ accessibility audit
   ├─ cumulative attention accounting
   ├─ provenance graph
   └─ accountable execution receipt
   ↓
allowed / suppressed UI
```

## JavaScript

```js
import { createInterfaceFirewall } from "aml-core";

const firewall = createInterfaceFirewall({ profile: "human_first" });

const result = firewall.enforce({
  transmission: "pricing_assistant",
  nodes: [{
    type: "message",
    identifier: "pricing",
    properties: {
      purpose: "Explain pricing clearly",
      content: "Simple pricing",
      attention_cost: 1,
      restoration_value: 2
    }
  }]
});

if (result.allowed) {
  render(result.html);
}
```

The result includes the final decisions, receipt, provenance verification, accessibility audit, and integrity checks.

## React-compatible adoption

ĀML includes a dependency-free adapter factory. Pass your existing React object once, then use an `AccountableUI` component around existing UI.

```jsx
import React from "react";
import { createAccountableUI } from "aml-core";

const AccountableUI = createAccountableUI(React);

export default function Pricing() {
  return (
    <AccountableUI
      id="pricing"
      purpose="Help the user understand pricing"
      attentionCost={1}
      restorationValue={2}
      policy="human_first"
      fallback={<p>This component was withheld by policy.</p>}
    >
      <ExistingPricingComponent />
    </AccountableUI>
  );
}
```

This does not require rewriting the application in `.aml` files. The adapter converts friendly component metadata into canonical ĀML intent and runs it through the same accountable pipeline.

## View Meaning

Traditional web tooling has **View Source**. ĀML adds **View Meaning**.

```js
import { viewMeaning } from "aml-core";

const meaning = viewMeaning(result.receipt);
console.log(meaning);
```

The report summarizes why each node exists, which policy governed it, its declared attention/restoration values, whether it rendered, and the integrity state of the receipt.

## Pull-request Meaning Gate

ĀML can also act before deployment.

A reusable composite GitHub Action lives at:

```text
actions/meaning-gate/action.yml
```

It can fail CI when a proposed AML change introduces high-risk semantic changes or changes from allowed to suppressed under the target policy.

Example inside this repository:

```yaml
- uses: ./actions/meaning-gate
  with:
    before-file: fixtures/before.aml
    after-file: fixtures/after.aml
    before-policy: calm_default
    after-policy: human_first
```

The underlying runner is also available directly:

```bash
node scripts/meaning-gate.js before.aml after.aml calm_default human_first
```

## Mainstream thesis

ĀML does not need to replace HTML or React to become useful.

It can sit **between machine intent and the interface humans receive**.

> HTML tells a browser what to display. ĀML tells the system why it deserves to be displayed, which rules allowed it, and how that decision can be checked.

ĀML is currently a research prototype. Its policy inputs are not claimed to be universal measurements of human wellbeing, and its accessibility checks do not replace WCAG conformance testing.
