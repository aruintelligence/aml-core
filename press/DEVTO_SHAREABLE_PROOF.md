# The smallest useful idea in ĀML: make UI decisions reproducible

**Status: PITCH**

A lot of AI interface discussion starts too high in the stack. Models, agents, policy systems, frameworks, standards.

ĀML starts with a smaller question:

**If an AI or application wants to put something on screen, can another person inspect why that element was allowed to render?**

The current prototype uses a deliberately simple rule:

```text
render_allowed = restoration_value >= attention_cost
```

Try the suppress state:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1

Then change `restoration_value` to `5`. The same element becomes allowed.

The important part is not that one equation solves interface design. It does not. The useful part is that the input, rule, decision, and AML source are visible and reproducible.

The repo goes one step further: CI executes the same accountable intent twice with a fixed timestamp and stream ID and requires the resulting receipt hashes, decision hashes, output hashes, and complete receipts to match.

It also verifies a balanced public fixture set: five ALLOW and five SUPPRESS cases.

That gives critics something concrete to attack.

Repository:
https://github.com/aruintelligence/aml-core

ĀML is a working research prototype, not a ratified standard. `attention_cost` and `restoration_value` are declared/model inputs, not validated objective measurements of human cognition.

**Ask:** open the demo, change `restoration_value`, copy the exact proof URL, screenshot the decision, and file what happened.
