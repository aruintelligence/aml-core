# ChargerGoGo Placements homepage real-screen pilot

This package applies the AML real-screen harness to `https://chargergogoplacements.com/`, captured on 2026-09-12 in a 1363 × 936 production viewport at scroll position 0,0.

## Experiment

The screen presents multiple competing attention targets: two announcement bars, repeated placement actions, an explainer path, a benefit panel, and a persistent placement assistant. The experiment asks whether the minimal AML rule distinguishes useful conversion paths from repeated promotional pressure, and whether a deterministic suppression should automatically become a shipping decision.

The labels are a project-directed operator review by OpenAI Codex. They are not independent validation or objective measurements. The receipt must therefore report `real_screen_evidence_eligible: false`.

## Reproduce

```bash
node tools/real-screen/aml-real-screen-pilot.mjs \
  --screen evidence/real-screen/2026-09-12-chargergogo-home/screen.html \
  --labels evidence/real-screen/2026-09-12-chargergogo-home/labels.json \
  --out evidence/real-screen/2026-09-12-chargergogo-home/receipt.json
```

The only rule is `render_allowed = restoration_value >= attention_cost`.

## Would we ship the suppressed UI?

**Partly.** We would ship suppression of the full-width sales-hours announcement bar because the same availability can remain in lower-attention contact context. We would **not** remove the bailment warning solely because this declared score falls below the gate: it carries risk-disclosure value that this minimal numeric rule does not separately model. The responsible change is to retain the warning while reducing its visual intensity and then reassess it.

This is a useful falsification result: AML deterministically identifies pressure, but the pilot does not establish that every suppression is safe to ship without domain-specific review.
