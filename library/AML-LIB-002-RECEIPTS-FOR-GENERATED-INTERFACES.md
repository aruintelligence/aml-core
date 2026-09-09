# AML-LIB-002 — Receipts for Generated Interfaces

**Status: SHIPPED**

A generated interface should leave behind more than pixels.

ĀML execution receipts are designed to preserve inspectable evidence about what the system declared, what policy inputs were evaluated, which interface elements were allowed or suppressed, and which output was produced.

A receipt can make questions answerable after the interface has changed:

- What purpose was declared?
- What attention cost and restoration value were used?
- Which rule produced the decision?
- Was the element allowed or suppressed?
- Can the receipt detect later mutation?
- Can another verifier reproduce the integrity check?

Receipts do **not** prove that a model's declared intent was truthful. They do not prove morality, legal compliance, or scientific validity of the input scores. Their value is narrower and more concrete: they turn otherwise ephemeral interface decisions into artifacts that can be inspected, replayed, compared, and challenged.

## Product path

1. Open the proof.
2. Change `restoration_value`.
3. Observe the decision.
4. Inspect View Meaning.
5. Reproduce deterministic receipt behavior locally.

Proof:
https://aruintelligence.github.io/aml-core/proof.html

View Meaning:
https://aruintelligence.github.io/aml-core/view-meaning.html

The research question is simple: if generated UI becomes normal, should consequential interface decisions be able to disappear without a record of why they were made?
