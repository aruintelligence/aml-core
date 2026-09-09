# AML-LIB-001 — The Interface Firewall

**Status: SHIPPED**

ĀML is an interface firewall between AI/app intent and pixels.

Modern systems can generate interface content faster than humans can review it. Existing controls usually operate on code, network access, component structure, or legal notice. ĀML explores a different boundary: require machine-facing interface intent to become inspectable before it becomes human-facing output.

Prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

That equation is intentionally simple. The important product idea is the boundary around it: declared purpose enters evaluation, an ALLOW or SUPPRESS decision is produced, and a receipt can preserve what was evaluated.

This does not mean ĀML knows the true motives of an AI, scientifically measures human attention, or guarantees ethical outcomes. It means the interface decision becomes reviewable instead of disappearing into generated pixels.

## Try it

SUPPRESS:
https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

ALLOW:
https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=5&lang=en

## Why this category matters

Generated UI changes the review problem. When a system can synthesize text, buttons, offers, prompts, nags, explanations, and layouts at runtime, teams need controls that operate closer to the human-interface boundary.

ĀML is a working research prototype, not a ratified global standard.
