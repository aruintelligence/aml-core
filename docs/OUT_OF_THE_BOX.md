# ĀML™ Out of the Box

ĀML should be useful before a developer learns the whole language.

This page gives three adoption paths: browser, application, and CI.

## 1. Browser: zero-install

Use the public GitHub Pages ES module directly:

```html
<script type="module">
  import { compileSourceBrowser } from "https://aruintelligence.github.io/aml-core/aml-browser.js";

  const source = `transmission "demo" {
    message "welcome" {
      purpose: "Explain the interface"
      attention_cost: 1
      restoration_value: 3
    }
  }`;

  const result = compileSourceBrowser(source);
  console.log(result.amt);
  console.log(result.renderDecisions);
</script>
```

Runnable source: [`examples/browser-drop-in.html`](../examples/browser-drop-in.html)

## 2. Existing app: AI Interface Firewall™

Clone the repository and use the public JavaScript API:

```js
import { createInterfaceFirewall } from "./index.js";

const firewall = createInterfaceFirewall({ profile: "human_first" });

const result = firewall.enforce({
  transmission: "assistant_ui",
  nodes: [{
    type: "message",
    identifier: "answer",
    properties: {
      purpose: "Answer the user's question",
      attention_cost: 1,
      restoration_value: 3,
      collects_personal_data: false
    }
  }]
});

console.log(result.allowed);
console.log(result.receipt);
```

The same core powers policy, consent, privacy, accessibility, attention, provenance, and receipt verification.

## 3. React: wrap an existing component

```jsx
import { createAccountableUI } from "./adapters/react.js";
import React from "react";

const AccountableUI = createAccountableUI(React);

export function Pricing() {
  return (
    <AccountableUI
      purpose="Explain pricing"
      attentionCost={1}
      restorationValue={3}
      policy="human_first"
      fallback={<p>This component was suppressed by policy.</p>}
    >
      <section>Simple pricing</section>
    </AccountableUI>
  );
}
```

## 4. Pull requests: Meaning Gate

ĀML can be used as a semantic regression gate in CI. The repository includes a reusable action surface under [`actions/meaning-gate`](../actions/meaning-gate/action.yml).

The gate can inspect semantic-risk changes and policy outcome changes instead of treating every source edit as equivalent.

## 5. Human-readable inspection: View Meaning™

Open:

https://aruintelligence.github.io/aml-core/view-meaning.html

Paste an execution receipt to inspect purpose, policy, modeled attention/restoration inputs, rationale, and render outcomes without reading raw pipeline internals.

## What this is — and is not

ĀML is a working research prototype for inspectable, policy-aware interface execution. It improves explicitness, reproducibility, and accountability artifacts. Current attention/restoration values remain model inputs, not validated measurements of cognition, wellbeing, harm, or ethics. Accessibility policy does not replace WCAG conformance testing.
