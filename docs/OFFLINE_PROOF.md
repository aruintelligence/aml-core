# ĀML offline proof

**Status: SHIPPED single-file demonstrator**

`docs/offline-proof.html` has no external JavaScript, CSS, fonts, images, package install, or build step.

Download the file once, disconnect, reopen it, and move the sliders.

It reproduces only the prototype equation:

```text
render_allowed = restoration_value >= attention_cost
```

It intentionally does **not** claim to reproduce the full AML compiler, policy engine, receipts, View Meaning, consent/privacy context, accessibility checks, signatures, or trust system.

Online source:

https://github.com/aruintelligence/aml-core/blob/main/docs/offline-proof.html

Live copy:

https://aruintelligence.github.io/aml-core/offline-proof.html

This exists so the core decision can be shown in classrooms, workshops, low-bandwidth environments, or offline review without a toolchain.

Open the full proof when connected. Change `restoration_value`. Screenshot the decision and receipt. File it.
