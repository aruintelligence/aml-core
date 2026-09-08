# Keep the HTML. Add ĀML.

**Status: PITCH**

The lowest-friction AML browser test does not require a framework migration.

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-dom-gate.js"></script>

<div
  data-aml-purpose="Create purchase urgency"
  data-aml-attention-cost="5"
  data-aml-restoration-value="1">
  Offer expires soon.
</div>
```

The SHIPPED prototype bridge scans AML-annotated DOM, evaluates the declared values with the browser compiler, and exposes a decision log at:

```js
window.__AML_DOM_DECISIONS__
```

Live demo:
https://aruintelligence.github.io/aml-core/dom-gate-demo.html

Documentation:
https://github.com/aruintelligence/aml-core/blob/main/docs/HTML_BRIDGE.md

This is a narrow bridge into existing HTML, not the full AML runtime.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
