# AML-LIB-003 — Why Generated UI Needs a Decision Boundary

**Status: SHIPPED**

AI-generated interfaces are not just generated text. They can choose urgency, ordering, prompts, offers, permissions, defaults, and interruptions at runtime.

Traditional review assumes much of the interface exists before deployment. Generated UI weakens that assumption. A product team may approve a component library while a runtime system still decides which component appears, why it appears, and how aggressively it competes for attention.

ĀML explores a decision boundary at that last step.

```text
machine intent
→ declared interface meaning
→ policy evaluation
→ ALLOW / SUPPRESS
→ pixels
→ receipt
```

The prototype rule is deliberately inspectable:

```text
render_allowed = restoration_value >= attention_cost
```

The scores are declared/model inputs. They are not objective measurements of cognition or wellbeing.

The larger point is architectural: generated interface behavior can become an explicit, testable decision rather than an invisible side effect of model output.

That enables review before deployment with Meaning Gate, inspection after execution with View Meaning, and reproducibility through receipts.

Live proof:
https://aruintelligence.github.io/aml-core/proof.html

ĀML is a working research prototype, not a ratified global standard.
