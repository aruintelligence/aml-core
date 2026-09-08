# Browser evidence packets

**Status: SHIPPED reference prototype**

ĀML's browser layer can now emit a local tamper-evident evidence packet that binds:

- a sealed `aml-dom-receipt/1`
- current strict-zone violations
- the exact page URL
- an evidence revision
- a SHA-256 integrity value over canonical JSON

The public demo is:

https://aruintelligence.github.io/aml-core/browser-evidence-demo.html

## One-script activation

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml.js"></script>
```

After AML produces a sealed receipt, the latest packet is exposed as:

```js
window.__AML_EVIDENCE__
```

Recent packets are available at:

```js
window.__AML_EVIDENCE_HISTORY__
```

## Verify locally

```js
import { verifyBrowserEvidence } from './aml-browser-evidence.js';

const result = await verifyBrowserEvidence(window.__AML_EVIDENCE__);
console.log(result.valid, result.reason);
```

## Receipt integrity

A sealed browser receipt carries:

```json
{
  "integrity": {
    "schema": "aml-integrity/1",
    "algorithm": "SHA-256",
    "canonicalization": "sorted-json-v1",
    "value": "...64 lowercase hex characters..."
  }
}
```

`verifyBrowserReceipt(receipt)` recomputes the digest from the receipt payload with `integrity` excluded and compares the exact result.

## Evidence integrity

`aml-browser-evidence/1` repeats the same pattern over the complete evidence packet, including the already-sealed receipt and current strict-zone violations.

This gives two checks:

1. receipt payload integrity
2. complete browser evidence packet integrity

Changing a purpose, score, decision, URL, timestamp, zone violation, or other bound field causes verification to fail.

## Why this matters

A visual interface can change after page load. AI-generated interfaces can also stream or mutate DOM nodes. A reproducible accountability layer therefore needs evidence that can travel independently of the current pixels.

The reference browser layer now explores this sequence:

```text
AI/app output
  -> AML declaration or strict-zone violation
  -> deterministic render decision
  -> browser receipt
  -> SHA-256 seal
  -> evidence packet
  -> independent local verification
```

## Evidence boundary

SHA-256 here establishes tamper evidence for exact canonical payload bytes. It does **not** prove:

- who authored the page
- that an AI's declared purpose is truthful
- that attention/restoration scores are objective measurements
- that the policy is morally correct
- that a remote server stored the same evidence
- that the packet is immutable or globally witnessed
- that the evidence is an official ĀRU authorization

A digital signature or externally anchored transparency mechanism is a separate trust layer.
