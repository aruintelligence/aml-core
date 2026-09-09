# ĀML AI Interface Firewall™ starter

This is the smallest useful ĀML adoption surface in the repository.

It is deliberately plain HTML so you can answer one question before reading the rest of the architecture:

> Can I put an accountability gate around an existing interface without rewriting my frontend?

## Run it

Download or clone this folder and open `index.html` in a modern browser with internet access.

The page loads the published browser bridge:

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-gate.js"></script>
```

Then it wraps ordinary HTML:

```html
<aml-gate
  purpose="Create urgency for a purchase"
  attention-cost="5"
  restoration-value="1">
  <button>Buy before the timer expires</button>
</aml-gate>
```

No React migration, bundler, package install, or server is required for this experiment.

## Change one number

Change:

```text
restoration-value="1"
```

to:

```text
restoration-value="5"
```

Reload the page and compare the decision.

The current demonstration rule is intentionally easy to inspect. The declared/model inputs are not claimed objective measurements of human cognition or wellbeing.

## Use your own UI

Replace the button inside `<aml-gate>` with one existing component or interaction from your application. Start with something where intent matters: a checkout CTA, consent prompt, notification, upgrade flow, AI-generated action, or administrative control.

For existing DOM without a wrapper, see [`docs/HTML_BRIDGE.md`](../../docs/HTML_BRIDGE.md).

For the broader adoption map, see [`ADOPT_AML.md`](../../ADOPT_AML.md).

For independent verification, see [`VERIFY.md`](../../VERIFY.md).

## What this starter proves — and what it does not

It demonstrates a narrow browser integration in which interface content carries declared purpose and gate inputs before rendering. It does not represent the entire ĀML runtime, cryptographic release chain, consent/privacy/accessibility system, production authorization model, or an objective determination that an interface is good, safe, legal, ethical, or truthful.

If this starter works in your stack, publish the integration. If it fails, publish the failure. External reproducible evidence is more useful than a private success claim.

— Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™
