# Show HN Launch Copy

**Status: DRAFT**

## Title

Show HN: ĀML — an interface firewall that makes AI-generated UI decisions inspectable

## Post body

I’ve been building ĀML, a prototype interface firewall that sits between AI/app intent and pixels.

The core prototype rule is deliberately simple:

```text
render_allowed = restoration_value >= attention_cost
```

The interesting part is not the equation by itself. ĀML carries declared meaning into policy evaluation and produces inspectable decisions and receipts.

Try it here:
https://aruintelligence.github.io/aml-core/playground.html

Inspect receipts here:
https://aruintelligence.github.io/aml-core/view-meaning.html

Source:
https://github.com/aruintelligence/aml-core

A dark-pattern proof fixture is in `demos/undeniable-proof/`.

This is a working research prototype, not a ratified standard and not a claim that subjective human outcomes have been scientifically solved. Code is MIT licensed.

The feedback I want most: break the assumptions, reproduce the decisions, and tell me which parts are too complicated to become useful.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## First comment

A few things I want to make explicit before the discussion starts:

1. ĀML does not replace HTML or React. The current implementation can sit in front of existing UI.
2. `attention_cost` and `restoration_value` are declared/model inputs in the prototype, not validated clinical measurements.
3. A receipt proves what the runtime evaluated and emitted; it does not prove that an AI told the truth about its intent.
4. I’m especially interested in independent implementations of the public fixtures and protocol contracts.
5. If the shortest useful version of this is just “a semantic CI gate for generated UI,” that is useful feedback too.

Repository issues are open for adversarial review and independent implementation work.
