# ĀML Proof Demo

**Status: DRAFT proof package; `before.html` and `after.aml` are runnable fixtures. The bundled receipt is illustrative until runtime replay output is wired into this folder.**

## What this shows

A countdown-pressure element declares:

```text
attention_cost: 5
restoration_value: 1
```

Under the prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

the countdown is suppressed while the ordinary purchase action can remain.

## Run it

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
node bin/aml.js compile demos/undeniable-proof/after.aml /tmp/aml-proof
```

Then open the playground:
https://aruintelligence.github.io/aml-core/playground.html

Paste `after.aml`, change `restoration_value`, and compile again.

Then inspect a real execution receipt in View Meaning:
https://aruintelligence.github.io/aml-core/view-meaning.html

## Witness ask

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File what happened.
