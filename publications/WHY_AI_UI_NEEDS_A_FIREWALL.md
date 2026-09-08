# Why AI-Generated UI Needs a Firewall

**Status: SHIPPED**

AI-generated interfaces create a new failure mode: output can be produced faster than a human team can review its purpose, pressure, data collection, accessibility context, or downstream effect.

Traditional frontend controls usually answer questions such as:

- Is this valid code?
- Does it render?
- Does it pass tests?
- Is this request authorized?

They do not usually ask:

> Why should this interface element deserve the user's attention?

ĀML explores that missing layer.

It sits between machine intent and pixels and requires declared meaning before rendering decisions are made.

Prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

The value is not the equation alone. The value is that the decision can leave behind a receipt that another person or tool can inspect.

A future AI product should not only be able to say:

> Here is the interface I generated.

It should increasingly be able to answer:

> Here is what I declared it was for, what rules judged it, why it rendered, and the receipt you can inspect.

Try the proof:
https://aruintelligence.github.io/aml-core/proof.html

This is a research prototype, not a claim of universal human-value measurement or standards-body adoption.
