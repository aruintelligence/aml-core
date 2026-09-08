# Generated UI needs a firewall, not just a renderer

**Status: PITCH**

AI can generate interface code faster than teams can review every decision embedded in it.

ĀML explores a narrow intervention: put an interface firewall between machine intent and pixels.

The public proof is intentionally small:

https://aruintelligence.github.io/aml-core/proof.html

Change `restoration_value`. The exact same interface element can move between ALLOW and SUPPRESS under a visible rule.

Then clone the repository and run:

```bash
node demos/undeniable-proof/replay-proof.mjs
```

CI requires deterministic replay of the proof material.

The claim is not that AML knows what a model "really meant." It evaluates declared intent and produces inspectable evidence around that evaluation.

That distinction matters if generated UI is ever going to be reviewed at machine speed without becoming a black box.

**Ask:** integrate one AML decision in front of one generated UI element and file what feels awkward.
