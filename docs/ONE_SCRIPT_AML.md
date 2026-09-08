# One-script AML browser integration

**Status: SHIPPED reference prototype**

Add one module:

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml.js"></script>
```

That reference bootstrap activates:

- `<aml-gate>` custom elements
- `data-aml-*` DOM declarations
- live DOM mutation watching for dynamically generated interfaces
- embedded `<script type="application/aml+json">` page manifests
- page-level `window.__AML_RECEIPT__`
- bounded `window.__AML_RECEIPT_HISTORY__`
- `aml-ready`, `aml-receipt`, and existing AML decision events

## Three declaration styles

### 1. Custom element

```html
<aml-gate purpose="Create urgency" attention-cost="5" restoration-value="1">
  <button>Act now</button>
</aml-gate>
```

### 2. Existing HTML attributes

```html
<div
  data-aml-purpose="Explain status"
  data-aml-attention-cost="1"
  data-aml-restoration-value="3">
  Saved.
</div>
```

### 3. Separate page manifest

```html
<script type="application/aml+json">
{
  "schema": "aml-page/1",
  "elements": [
    {
      "selector": "#status",
      "purpose": "Explain status",
      "attention_cost": 1,
      "restoration_value": 3
    }
  ]
}
</script>
```

The third pattern lets presentation remain ordinary HTML while meaning is declared separately for machine inspection.

## Dynamic AI interfaces

The live DOM layer watches for new AML-declared nodes and changes to declared purpose/attention/restoration values. It does not observe AML's own output attributes, preventing the reference observer from recursively triggering itself.

## Receipts

The latest page-level browser receipt is exposed at:

```js
window.__AML_RECEIPT__
```

Recent revisions are available at:

```js
window.__AML_RECEIPT_HISTORY__
```

The reference history is bounded to 50 receipts.

## Evidence boundary

This surface demonstrates inspectable deterministic policy behavior over declared/model inputs. It does not make declared purpose truthful, does not establish that current scores objectively measure cognition or wellbeing, and does not replace application security, privacy review, accessibility conformance testing, or production policy governance.
