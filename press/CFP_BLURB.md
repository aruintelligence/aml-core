# Conference CFP Blurb

**Status: DRAFT**

## Title

**View Meaning: Making AI-Generated Interface Decisions Inspectable**

## Blurb

AI systems can generate interface variants faster than teams can manually review them. ĀML is a working research prototype that treats declared interface purpose and policy-relevant metadata as executable inputs before rendering. Its baseline prototype rule is simple—`render_allowed = restoration_value >= attention_cost`—but the broader experiment is about inspectability: semantic diffs, policy decisions, CI gates, execution receipts, and a View Meaning inspector that exposes why an element rendered or was suppressed. This talk would show a dark-pattern proof fixture, reproduce the decision live, inspect the receipt, and discuss the hard limitations: declared intent can be false, policy values are not universal ethics, and current attention/restoration values are model inputs rather than validated cognitive measures. The goal is not to announce a new standard; it is to ask whether AI-generated interfaces need a reviewable accountability layer before pixels reach a person.

Demo: https://aruintelligence.github.io/aml-core/playground.html

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
