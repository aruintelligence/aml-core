# EthicalRenderGate™ Explained

EthicalRenderGate™ is the current policy checkpoint in the ĀML™ prototype. It evaluates declared interface inputs before final browser output is emitted.

The present rule is deliberately simple:

```text
render_allowed = restoration_value ≥ attention_cost
```

This is not asserted as a universal moral formula. It is an inspectable baseline that lets the project demonstrate policy-aware compilation end to end.

## Three outcomes

A proposed element can currently resolve toward:

- **allowed** — it passes the configured gate;
- **degraded** — it is close enough to the threshold for a reduced presentation;
- **suppressed** — it fails the configured policy strongly enough that output is withheld.

## Why a gate belongs before rendering

If policy is applied only after HTML exists, the system is evaluating a final artifact after much of the author's original semantic intent has been flattened into implementation detail.

ĀML instead carries declared meaning into an Abstract Meaning Tree and evaluates that representation before emitting final output.

## Why the decision record matters

The compiler can emit `render_decision.json`, allowing reviewers and automated tests to inspect what happened. A policy result therefore becomes a reproducible artifact instead of an invisible runtime choice.

## Replaceable by design

The current gate should be treated as one model, not the model. Future research can compare alternate formulas, accessibility rules, user-selected policies, domain-specific gates, and empirically validated systems against the same meaning-bearing source representation.

Live lab: https://aruintelligence.github.io/aml-core/

Repository: https://github.com/aruintelligence/aml-core

EthicalRenderGate™ and ĀML™ are claimed marks of ĀRU Intelligence Inc.™
