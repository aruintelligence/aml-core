# Kinthria™ homepage — AML experiment series

Production target: `https://kinthria.com/`

Date: 2026-09-12

This package records a sequence of narrowly scoped AML interface-governance experiments against the Kinthria homepage source. The experiments are intended to reduce redundant presentation while preserving the site's research integrity, evidence standards, product explanation, pricing, and restoration paths.

## Evidence boundary

The attention-cost and restoration-value concepts used by AML are project-directed operator-review judgments. They are **not objective measurements** of cognition, attention, usability, conversion, wellbeing, accessibility, or business performance. A code change, successful build, or deterministic receipt does not establish that a production user outcome improved.

The exact production post-change rendered-screen capture, hashes, and reproducible real-screen receipt have not yet been collected in this chat. Therefore this report does **not** claim production remediation has been verified and does not claim independent validation.

## Experiment 1 — focus primary navigation

Primary navigation was reduced from eight content links to five:

- Services
- Legacy Profiles
- How It Works
- Pricing
- About

Home, Portfolio, and Research were removed from the primary navigation presentation. Portfolio and Research remain available elsewhere in the interface, including footer/restoration paths; their underlying content was not deleted.

Base44 checkpoint: `6aa5f387acd8cd8b0991d4d2`

Source commit: `4a5b203761a13d36effee376538bb08ecea688bd`

## Experiment 2 — clarify hero value and proof path

The hero description was rewritten to state the product more directly: Kinthria researches family evidence and turns it into a museum-quality Legacy Profile designed to preserve the person, proof, and story.

The secondary hero CTA changed from `View Demonstration` to `See a Finished Profile`, making the destination and restoration value more explicit without removing the demonstration.

Base44 checkpoint: `6aa5f537404be2bbc48e4cce`

Source commit: `3e08c08ebf0d9b74290f19ec30e076aa1128117b`

## Experiment 3 — compress the process

The How It Works sequence was reduced from eight presentation steps to six. The former final three steps — publishing on Kinthria, social sharing, and FamilySearch improvement — were consolidated into one final delivery step, `Publish & share the legacy`.

The underlying capabilities were preserved in the consolidated description: permanent Kinthria profile, evidence-based FamilySearch improvements when appropriate, social publication, and descendant/researcher discoverability.

Base44 checkpoint: `6aa5f9151f18d19edb4b45d8`

Source commit: `90f7a7a8caeae8506cb164a051d611047f58faab`

## Verification performed

For Experiments 2 and 3, the application build and lint commands completed successfully. Experiment 3 specifically passed:

```text
npm run build
npm run lint -- --quiet
```

The only observed warning concerned stale `caniuse-lite` browser data; it did not fail the build or lint run.

## Preserved high-restoration material

The experiment pass intentionally preserves material whose removal could destroy important meaning or trust, including:

- evidence-before-narrative positioning;
- authentic-photograph policy;
- explicit uncertainty and conflicting-evidence handling;
- pricing and research-rate disclosure;
- historical standards;
- inquiry privacy/consent language;
- the explicit `Future vision — not current features` boundary;
- access to Portfolio and Research outside the primary navigation.

## Next falsifiable experiments

Candidate tests include CTA consistency, inquiry-form progressive disclosure, repeated proof-path wording, section-order attention, portfolio presentation density, and restoration-path verification. Each should be treated as a separate intervention and should preserve the distinction between operator judgment and deterministic policy.

## Required production closeout

Before this package can be described as a verified real-screen before/after experiment, capture the exact rendered production screen after publication, preserve the screen/DOM metadata and SHA-256 hashes, identify the reviewed UI elements, store labels separately with explicit provenance, run the AML harness twice, and compare receipts byte-for-byte.

Until that occurs, `real_screen_evidence_eligible` should be treated as `false`.
