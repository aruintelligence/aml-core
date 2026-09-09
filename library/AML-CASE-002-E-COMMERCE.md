# AML-CASE-002 — E-Commerce

**Status: DRAFT casebook built on SHIPPED AML primitives**

Commerce interfaces are a natural stress test because small UI decisions can create pressure at exactly the moment a person is deciding whether to spend money.

## Candidate AML patterns

- countdown pressure
- forced upsell prompts
- repeated scarcity messages
- add-on defaults
- checkout data requests
- subscription renewal prompts
- calm price explanations
- clear purchase controls

The public proof uses countdown pressure because the mechanism is easy to inspect:

```text
attention_cost = 5
restoration_value = 1
→ SUPPRESS
```

A normal purchase action can independently remain ALLOW.

The value is not “AML bans marketing.” It is that product teams can state a policy, evaluate individual interface elements, and keep evidence of the decision.

## Pilot question

Can a checkout team review generated urgency and upsell UI through Meaning Gate before deployment and inspect the executed decision afterward through a receipt?

Proof:
https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en
