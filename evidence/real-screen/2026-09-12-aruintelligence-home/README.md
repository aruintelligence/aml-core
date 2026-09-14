# ĀRU Intelligence homepage real-screen pilot

This evidence package applies the AML real-screen harness to the live production homepage at `https://aruintelligence.com/`, captured on 2026-09-12 in a 1363 × 936 browser viewport at scroll position 0,0.

## Evidence boundary

This is a real production screen, not the synthetic conformance fixture. The screenshot, rendered HTML, and browser DOM were hashed during capture. `screen.html` is the stable marker-bearing semantic extraction passed to the harness; `capture-metadata.json` binds it to the untouched browser artifacts.

The labels are a project-directed operator review performed by OpenAI Codex. They are not independent validation and the numeric values are not objective measurements of human attention, restoration, benefit, wellbeing, or behavior. Consequently, the receipt is expected to report `real_screen_evidence_eligible: false` even though the underlying screen is a live production screen.

## Reproduce

```bash
node tools/real-screen/aml-real-screen-pilot.mjs \
  --screen evidence/real-screen/2026-09-12-aruintelligence-home/screen.html \
  --labels evidence/real-screen/2026-09-12-aruintelligence-home/labels.json \
  --out evidence/real-screen/2026-09-12-aruintelligence-home/receipt.json
```

The only decision rule is:

```text
render_allowed = restoration_value >= attention_cost
```

## Would we ship the suppressed UI?

**No—not on this evidence alone.** The `founding-circle` navigation promotion is deterministically SUPPRESS under the declared labels, but a single project-directed review is not enough evidence to remove or hide a production business element. The practical next step would be to redesign or reduce its prominence, then obtain user research or an independent review before shipping suppression.

This result is useful precisely because the deterministic policy output and the product shipping decision remain separate and inspectable.
