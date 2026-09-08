# Canonical ĀML Proof Links

**Status: SHIPPED**

Use these links when you need a reproducible public example.

## Default proof lab

https://aruintelligence.github.io/aml-core/proof.html

## Known SUPPRESS state

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1

Expected prototype decision: `SUPPRESS`.

## Boundary state

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=5

Expected prototype decision: `ALLOW` because equality passes the current prototype rule.

## High-restoration ALLOW state

https://aruintelligence.github.io/aml-core/proof.html?attention=2&restoration=8

Expected prototype decision: `ALLOW`.

## Embeddable card

https://aruintelligence.github.io/aml-core/proof-card.html?attention=5&restoration=1

## Rule

```text
render_allowed = restoration_value >= attention_cost
```

These URLs demonstrate software behavior only. The numeric inputs are declared/model values and are not represented as objective measurements of human cognition or wellbeing.

**Witness ask:** open one link, reproduce the expected result, then change a value and file the exact resulting URL.
