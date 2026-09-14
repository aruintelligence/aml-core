# ĀML™ Real-Screen Evidence Contract

This document explains the evidence discipline for ĀML experiments against actual rendered interfaces.

The **canonical machine-readable contract** for new evidence packages is `schema/real-screen-evidence-manifest.schema.json`, with repository guidance in `evidence/real-screen/README.md`. This document is explanatory and must not be treated as a competing schema.

The purpose is reproducibility and provenance. It does not convert subjective review labels into objective measurements of cognition, attention, wellbeing, accessibility, morality, conversion, or business performance.

## Required separation

A real-screen experiment should keep these layers distinct:

1. **production observation** — what was actually rendered or captured;
2. **review labels** — explicit human or model-assisted judgments and their provenance;
3. **deterministic policy** — the rule/version applied to those declared inputs;
4. **receipt** — the resulting machine-readable decision evidence;
5. **remediation** — code or content changes made after review;
6. **after observation** — a new production capture proving what was actually deployed.

Source-code remediation is not, by itself, production-after evidence.

## Machine-readable manifest

New real-screen packages SHOULD include `manifest.json` conforming to `schema/real-screen-evidence-manifest.schema.json` and follow `evidence/real-screen/README.md`.

The manifest is the primary index tying together source/capture provenance, artifact hashes, label provenance, ĀML version or commit, policy identity, receipt hashes/root, rerun status, optional after-state evidence, `real_screen_evidence_eligible`, and the experiment claim boundary.

Legacy packages should be migrated additively when reliable metadata is available. Do not rewrite historical capture bytes, labels, receipts, hashes, or provenance merely to make an older experiment look complete.

## Recommended experiment directory

```text
evidence/real-screen/YYYY-MM-DD-slug/
  manifest.json
  README.md
  capture-metadata.json
  screen.html
  labels.json
  receipt.json
  REMEDIATION.md            # when a change is made
  after/                    # when production after-capture exists
    capture-metadata.json
    screen.html
    labels.json
    receipt.json
```

Additional untouched screenshot, DOM, network, or browser artifacts may be preserved when the capture system supports them.

## Capture metadata

Capture evidence SHOULD preserve, where available:

- source URL;
- capture date/time and timezone;
- capture agent/tool;
- viewport and device-pixel-ratio;
- scroll position;
- page title;
- hashes and byte sizes of screenshot, rendered HTML, DOM snapshot, or other preserved artifacts;
- a clear description of which artifact is passed to the ĀML harness;
- limitations of the capture.

A hash proves byte identity. It does not prove that a label is correct or independent.

## Labels and provenance

Labels SHOULD remain separate from the captured screen material and identify for each reviewed element, where applicable:

- stable element/review ID;
- declared purpose;
- `attention_cost`;
- `restoration_value`;
- provenance source kind;
- reviewer/author identity or role where appropriate;
- source reference tying the judgment to the capture;
- whether the review is project-directed;
- any disagreement or uncertainty worth preserving.

The project MUST NOT describe these numeric labels as objective physiological, neurological, psychological, clinical, or scientific measurements unless independent evidence actually establishes that claim.

## Policy binding

The receipt and manifest SHOULD identify the exact policy/rule and software state used to evaluate the labels. For the minimal prototype gate:

```text
render_allowed = restoration_value >= attention_cost
```

A deterministic result proves that the declared inputs and rule reproduce the same decision. It does not prove that the inputs are universally correct.

## Deterministic rerun

Where feasible:

1. run the harness once;
2. preserve the receipt;
3. run it again from the same captured input and labels;
4. compare the resulting receipt bytes or documented deterministic fields;
5. record the rerun result in the manifest and supporting notes.

Any nondeterminism should be surfaced, not hidden.

## `real_screen_evidence_eligible`

A project-controlled experiment SHOULD remain `real_screen_evidence_eligible: false` unless the repository's stated evidence requirements for that status are actually met.

The flag must not be upgraded merely because:

- the source URL is public;
- the page belonged to ĀRU or a customer;
- the project generated a receipt;
- a build passed;
- the project author agrees with the labels.

## Before/after work

An after-state should be treated as proven only after a new production capture is obtained and bound through the canonical manifest structure. Preserve the previous capture rather than overwriting it.

A remediation report SHOULD state:

- exact element(s) changed;
- what capability or restoration path was preserved;
- before checkpoint/commit where available;
- after checkpoint/commit where available;
- whether production publication is verified;
- what claims are *not* established by the intervention.

## Capability preservation

A SUPPRESS decision should not automatically mean deletion. For important controls, test whether the useful capability remains reachable through a lower-burden path. This project refers to that engineering pattern as **suppression without capability destruction**.

## External sites

Observational experiments on public third-party interfaces must not imply partnership, endorsement, audit authority, certification, or maintainer approval. Respect applicable terms, access controls, copyright, privacy, and security boundaries.

## Claim boundary

A real-screen evidence package can establish reproducibility of captured bytes, declared labels, policy inputs, and deterministic output to the extent those artifacts are actually preserved and bound. On its own it does **not** establish conversion lift, user preference, cognitive benefit, accessibility conformance, safety, scientific validity, regulatory compliance, or independent adoption.
