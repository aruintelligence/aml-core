# ĀML in one custom element

**Status: PITCH**

You do not need to rewrite a frontend to test ĀML.

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-gate.js"></script>

<aml-gate
  purpose="Create urgency"
  attention-cost="5"
  restoration-value="1">
  <button>Buy before the timer ends</button>
</aml-gate>
```

The SHIPPED prototype web component evaluates the wrapper with the browser AML compiler and suppresses it when:

```text
restoration_value < attention_cost
```

Live demo:
https://aruintelligence.github.io/aml-core/aml-gate-demo.html

Source:
https://github.com/aruintelligence/aml-core/blob/main/docs/aml-gate.js

This is intentionally the small browser path, not a claim that the web component contains every AML runtime feature.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
