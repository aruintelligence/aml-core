# ĀML HTML bridge

**Status: SHIPPED prototype**

Existing HTML can opt into the prototype ĀML render rule with data attributes and one module import.

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-dom-gate.js"></script>

<div
  data-aml-purpose="Create purchase urgency"
  data-aml-attention-cost="5"
  data-aml-restoration-value="1">
  Offer expires soon.
</div>
```

The bridge evaluates elements carrying both score attributes. Under the prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

an element with `5 / 1` is suppressed, while an element with `1 / 3` is allowed.

The bridge uses the browser AML compiler and records the page-level decision list in:

```js
window.__AML_DOM_DECISIONS__
```

You can also listen for completion:

```js
document.addEventListener('aml-dom-gated', event => {
  console.log(event.detail.decisions);
});
```

This bridge is intentionally narrow. It is not a substitute for the full AML runtime's richer policy, consent, privacy, accessibility, receipt, or trust features.

Live demo:

https://aruintelligence.github.io/aml-core/dom-gate-demo.html

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
