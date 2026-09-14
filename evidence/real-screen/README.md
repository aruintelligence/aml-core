# ĀML™ Real-Screen Evidence Corpus

This directory contains project-authored real-screen experiments. The purpose of the corpus is reproducibility, not promotional proof.

## Canonical manifest for new experiments

New experiments should include a `manifest.json` conforming to:

`schema/real-screen-evidence-manifest.schema.json`

The manifest should identify, without guessing or backfilling unavailable facts:

- experiment identifier;
- source URL and capture time when known;
- capture method and provenance;
- every preserved screen/source artifact and its SHA-256;
- a separate labels file, its SHA-256, and explicit label provenance;
- the exact ĀML version or commit and policy used;
- receipt path, SHA-256, and receipt root when present;
- whether a deterministic rerun was actually performed and whether it was byte-identical;
- after-state evidence when captured;
- an explicit `real_screen_evidence_eligible` boolean;
- a plain-language claim boundary.

## Evidence boundary

`attention_cost`, `restoration_value`, and similar review labels in this corpus are declared project/operator judgments unless a specific experiment establishes a different provenance. They are not objective measurements of cognition, attention, neurological state, psychology, wellbeing, morality, accessibility outcomes, or clinical outcomes.

A source-code change, successful build, deployment instruction, or business result is not automatically a verified production after-state. Production verification requires its own capture and provenance.

A project-authored experiment is not independent validation. Repository tests, GitHub traffic, clone counts, outreach, and internal reproduction do not establish external adoption.

## Eligibility rule

Set `real_screen_evidence_eligible: true` only when the experiment actually satisfies the project’s stated real-screen evidence requirements, including sufficient capture provenance, hashable artifacts, labels/provenance, exact policy/runtime identification, and reproducible decision evidence.

When evidence is incomplete, preserve it and set the value to `false`. Do not manufacture missing timestamps, screenshots, hashes, browser metadata, or post-deployment observations.

## Legacy experiment directories

Experiments created before this manifest contract may remain in their historical shape. They should be treated as legacy/unmigrated unless and until their existing artifacts can be mapped into `manifest.json` without inventing missing information.

Migration is additive: do not modify historical captured artifacts merely to satisfy the new schema, because doing so would invalidate the very hashes the corpus is intended to preserve.

## Recommended directory shape

```text
evidence/real-screen/<experiment-id>/
  README.md
  manifest.json
  capture-metadata.json
  labels.json
  receipt.json
  screen.html / screenshot.png / other captured artifacts
  after/                     # optional, only when actually captured
```

The manifest is the index. The underlying evidence files remain the evidence.
