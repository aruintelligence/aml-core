# Conference Talk Proposal

**Status: PITCH — ready to submit**

## Title
**The Interface Firewall: Making AI-Generated UI Inspectable Before It Becomes Pixels**

## Abstract
AI systems can now generate user-facing interfaces at a speed and variability that traditional review processes were not designed to handle. ĀML is a working research prototype exploring a narrow idea: place an inspectable decision layer between machine intent and pixels. The prototype asks interface elements to declare purpose, attention cost, and restoration value; a policy decides ALLOW or SUPPRESS; and the execution can leave behind a receipt for later inspection. This talk demonstrates a dark-pattern case that flips from SUPPRESS to ALLOW by changing one declared value, then follows the decision into View Meaning, deterministic replay, cross-runtime verification, and an immutable verifier snapshot. The emphasis is not on claiming a universal ethics formula. It is on making generated interface decisions explicit, reproducible, and challengeable.

## Audience takeaway
Attendees leave with one runnable proof URL, one small integration example, and one question for their own AI products:

> Can this interface explain why the human saw it?

Proof: https://aruintelligence.github.io/aml-core/proof.html
