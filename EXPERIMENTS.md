# ĀML Real-World Experiments

This is the front door for ĀML experiments against real interfaces.

ĀML is being tested as an **auditable interface-governance layer**: capture what a user can actually encounter, attach explicit review labels and provenance, apply deterministic policy, preserve a receipt, make a narrowly scoped remediation, and then test the changed interface again.

The prototype attention gate used by this cohort is intentionally small:

```text
render_allowed = restoration_value >= attention_cost
```

The numeric inputs are declared operator judgments. They are not objective measurements of cognition, attention, wellbeing, morality, accessibility, or business performance.

## Owned-site experiments

| Experiment | What is being tested | Status |
| --- | --- | --- |
| [ĀRU Intelligence homepage](evidence/real-screen/2026-09-12-aruintelligence-home/) | Can a real production screen be captured, labeled, hashed and deterministically gated? | Real-screen pilot |
| [ChargerGoGo Placements](evidence/real-screen/2026-09-12-chargergogo-home/) | Can a suppression decision lead to a responsible before/after remediation rather than blind deletion? | Before/after package |
| [Portland ATM Placement](evidence/real-screen/2026-09-12-portland-atm-placement/) | Can redundant desktop presentation be reduced while important functions and regional content remain available? | Remediation documented; exact after-capture pending |

## Public-site research cohort

[React, Vite and MDN](evidence/real-screen/2026-09-12-open-source-homepages/) are included as an ethical public-screen cohort. These are observational project-directed experiments, not endorsements, partnerships, audits, certifications, or claims about the maintainers of those projects.

## The capability being explored

The important idea is **suppression without capability destruction**.

Traditional UI optimization often jumps from an observation to a redesign. ĀML experiments instead preserve an inspectable chain:

1. Capture the interface state.
2. Preserve hashes and metadata.
3. Identify the exact UI targets under review.
4. Store labels separately with provenance.
5. Apply a deterministic rule.
6. Preserve the resulting receipt.
7. Review whether a SUPPRESS result is actually safe to ship.
8. Make the smallest defensible change.
9. Capture the changed production interface again.
10. Reproduce the receipt and compare deterministic output.

This separates four things that are often blurred together: **human judgment, machine policy, code remediation, and production observation**.

## Research directions

The current experiments suggest several falsifiable extensions worth testing rather than merely claiming:

- **Capability-preservation checks:** prove that suppressed presentation did not make critical actions unreachable.
- **Attention budgets:** test whether a screen can declare a maximum aggregate attention cost and deterministically choose among competing elements.
- **Policy profiles:** compare the same interface under different explicit policies without changing the underlying application code.
- **Semantic diffs:** distinguish a cosmetic DOM change from a meaningful change in purpose, authority, consent, or rendering decision.
- **Counterfactual receipts:** show what would have rendered under alternate declared label values or policy versions.
- **Reviewer disagreement:** preserve multiple reviewers' labels rather than hiding disagreement behind an averaged score.
- **Temporal drift:** recapture the same production screen over time and detect when interface meaning or policy behavior changes.
- **Cross-renderer reproduction:** test whether different frontend implementations reach the same policy decision from the same meaning inputs.
- **Adversarial UI tests:** intentionally construct redundant urgency, duplicate calls to action, or policy bypass attempts and verify whether the gate catches them.
- **Restoration-path proofs:** attach evidence that an important suppressed control still has a lower-attention path available to the user.

These are research hypotheses and engineering directions, not validated capabilities until implemented and reproduced.

## What would make the evidence stronger?

Independent reproduction. A third party should be able to take the same captured inputs and labels, run the documented rule, and report PASS, FAIL, or MIXED. Disagreement about the labels is also useful evidence because the labels are intentionally explicit rather than disguised as objective truth.

## Evidence boundary

Project-authored demonstrations are not independent validation. A deterministic receipt proves reproducibility of the declared inputs and rule; it does not prove that the declared values are scientifically correct or that a UI change improves conversion, usability, accessibility, safety, or wellbeing.

The project is strongest when those boundaries remain visible.
