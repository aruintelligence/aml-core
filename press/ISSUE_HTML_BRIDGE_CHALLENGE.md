# Issue draft — integrate AML data attributes outside aml-core

**Status: PITCH**

## Goal

Use the SHIPPED AML HTML bridge on an independently maintained public page.

## Start

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-dom-gate.js"></script>
<div data-aml-purpose="Create urgency" data-aml-attention-cost="5" data-aml-restoration-value="1">Offer expires soon.</div>
```

## Acceptance

- page/repository maintained outside `aruintelligence/aml-core`
- exact source link posted
- one expected ALLOW and one expected SUPPRESS case
- `window.__AML_DOM_DECISIONS__` result included
- integration friction or browser incompatibility documented
- no certification/endorsement claim implied

A failed integration counts as useful evidence if reproducible.
