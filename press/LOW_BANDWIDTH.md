# ĀML Low-Bandwidth / No-Build Path

**Status: DRAFT**

You do not need Node, npm, a bundler, or a framework to understand the core proof.

## Option 1 — One browser page

Open:
https://aruintelligence.github.io/aml-core/playground.html

Paste:

```aml
transmission "low_bandwidth_demo" {
  message "pressure" {
    purpose: "Create urgency"
    content: "Act now"
    attention_cost: 5
    restoration_value: 1
  }
}
```

Compile it.

Then change:

```text
restoration_value: 1
```

to:

```text
restoration_value: 6
```

Compile again and compare the decision.

## Option 2 — Save one HTML file

Use the zero-install browser-module example in `examples/browser-drop-in.html`.

No package registry is required for this first experience.

## What to record

- original values;
- changed values;
- allow/suppress result;
- receipt or View Meaning output;
- browser/device.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
