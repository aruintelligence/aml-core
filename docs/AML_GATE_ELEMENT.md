# `<aml-gate>` — zero-install browser gate

**Status: SHIPPED prototype**

The fastest browser integration path is one module plus one wrapper element.

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-gate.js"></script>

<aml-gate
  purpose="Create urgency during checkout"
  attention-cost="5"
  restoration-value="1">
  <button>Buy before the timer ends</button>
</aml-gate>
```

The custom element uses the same browser AML compiler exposed by `aml-browser.js`.

If `restoration_value < attention_cost`, the wrapped content is suppressed. If `restoration_value >= attention_cost`, it remains visible.

Listen for the decision:

```js
document.addEventListener('aml-decision', event => {
  console.log(event.detail);
});
```

This is a lightweight browser adoption surface, not a replacement for full policy, consent, privacy, accessibility, or receipt verification in the Node/runtime implementation.

Open the live demo:

https://aruintelligence.github.io/aml-core/aml-gate-demo.html

Open the proof. Change `restoration_value`. Screenshot the decision and receipt. File it.
