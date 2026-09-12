# Real-screen AML pilot

The next credibility step is not another architecture layer. It is applying the minimal public gate to a screen that somebody actually ships.

This harness deliberately keeps that test narrow:

1. Capture an HTML snapshot of the screen under test.
2. Add stable `data-aml-id` markers to the interface elements being evaluated. The harness does not require replacing React, Vue, server-rendered HTML, or another UI stack.
3. Obtain a separate label file from the person or process responsible for the assessment. Each label declares `purpose`, `attention_cost`, `restoration_value`, and provenance.
4. Bind the label file to the exact screen snapshot with SHA-256.
5. Run the pilot verifier.

```bash
node tools/real-screen/aml-real-screen-pilot.mjs \
  --screen path/to/screen.html \
  --labels path/to/labels.json \
  --out aml-real-screen-receipt.json
```

The minimal gate is exactly:

```text
render_allowed = restoration_value >= attention_cost
```

Equality is ALLOW. A lower restoration value is SUPPRESS. This harness does not invent a DEGRADE threshold; a degradation rule must be separately declared if a pilot needs one.

## Label provenance matters

The verifier distinguishes a deterministic decision from evidence quality. A project-authored synthetic label can test the machinery, but it cannot satisfy `real_screen_evidence_eligible`.

For that field to be true, every evaluated element must have:

- `declared_by_project: false`, and
- a non-synthetic `source_kind` such as `independent_review`, `operator_review`, `user_research`, or `measured_proxy`.

That still does **not** make the numbers objective measurements of human attention, harm, wellbeing, or restoration. It only makes the source of the labels explicit and auditable.

## What to publish from a real pilot

Publish the exact screen SHA-256, the exact labels file SHA-256, the generated receipt, the label provenance, whether any element was suppressed, and whether the product team would actually ship that suppression. A useful pilot is allowed to return an inconvenient answer.

Project-controlled fixtures in `conformance/real-screen/` are synthetic regression tests only. They are not evidence that AML has been validated in an independent product.
