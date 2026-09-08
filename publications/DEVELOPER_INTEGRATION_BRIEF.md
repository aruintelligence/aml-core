# Developer Integration Brief

**Status: SHIPPED**

ĀML does not require a frontend rewrite.

Three entry paths:

## 1. One wrapper

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-gate.js"></script>
<aml-gate purpose="Create urgency" attention-cost="5" restoration-value="1">
  <button>Act now</button>
</aml-gate>
```

## 2. Existing DOM

```html
<div data-aml-purpose="Create urgency"
     data-aml-attention-cost="5"
     data-aml-restoration-value="1">
  Offer expires soon.
</div>
```

## 3. HTTP service

Run the reference service and place AML between an AI backend and your UI layer.

Start here:
https://github.com/aruintelligence/aml-core/blob/main/docs/TRY_AML_10_MINUTES.md

The goal is simple: keep your stack, add an inspectable decision boundary.
