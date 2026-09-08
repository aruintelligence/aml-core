# ĀML — 150-Word Abstract

**Status: DRAFT**

ĀML (ĀRU Meaning Language) is a working research prototype for making AI- and application-generated interface decisions inspectable before and after rendering. Rather than treating interface output only as pixels or markup, ĀML carries declared purpose and policy-relevant metadata into an evaluation layer that can decide whether an element should render and can emit a receipt describing the decision. The prototype uses a simple baseline relation, `render_allowed = restoration_value >= attention_cost`, where both values are declared/model inputs rather than validated measurements of human cognition or wellbeing. The current implementation includes a compiler, policy profiles, semantic and policy diffs, cumulative attention accounting, accessibility-oriented checks, execution receipts, View Meaning inspection, GitHub CI gates, HTTP integration, conformance fixtures, and public interoperability experiments. ĀML does not claim global-standard status, regulatory compliance, or verified ethical correctness. Its present research value is inspectability, reproducibility, explicit policy control, and independently testable interface-accountability artifacts.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
