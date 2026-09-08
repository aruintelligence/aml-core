# ĀML Proof Demo

**Status: SHIPPED proof package. Deterministic replay and the balanced five-ALLOW/five-SUPPRESS fixture set are enforced in CI.**

## What this proves

A countdown-pressure element declares:

```text
attention_cost: 5
restoration_value: 1
```

Under the prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

the countdown is suppressed while the ordinary purchase action remains allowed.

The same fixed intent is also executed twice with the same timestamp, stream ID, profile, and context. CI requires:

- both receipts verify
- both `receipt_sha256` values match exactly
- both decision hashes match exactly
- both output hashes match exactly
- the complete receipt objects are deeply equal

## Run the deterministic replay

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
node demos/undeniable-proof/replay-proof.mjs
```

## Verify the balanced public fixture set

```bash
node scripts/check-flood-fixtures.js
```

That command requires five public fixtures to ALLOW and five to SUPPRESS under `restorative_v1`.

## Change the decision yourself

Open:
https://aruintelligence.github.io/aml-core/playground.html

Paste `after.aml`, change `restoration_value`, and compile again.

Then inspect an execution receipt in View Meaning:
https://aruintelligence.github.io/aml-core/view-meaning.html

## Evidence boundary

This proves deterministic software behavior for fixed inputs. It does not prove that `attention_cost` or `restoration_value` are objective measures of human cognition, or that the selected policy is universally correct.

## Witness ask

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File what happened using the **AML witness reproduction** issue template.
