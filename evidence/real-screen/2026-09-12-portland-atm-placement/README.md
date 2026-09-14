# Portland ATM Placement AML experiment

Target: `https://portlandatmplacement.com/`

This report documents an AML UI-remediation experiment on an owned production site. The goal is to test a practical question: can an explicit, deterministic attention rule identify redundant presentation while preserving the functions users need?

## Experiment 1: desktop navigation

The before capture was taken on 2026-09-12 at 1363 x 936. It produced 9 ALLOW and 2 SUPPRESS decisions. Receipt root: `d541ec219b58f03e0c80af4c288e1730e1cb7b72c9509ae67839c4d237fafabb`.

The two declared suppression labels were:

- Duplicate desktop Ask ATM AI: attention_cost 3, restoration_value 1.
- Regional desktop navigation group: attention_cost 4.5, restoration_value 2.

The only rule is:

`render_allowed = restoration_value >= attention_cost`

The remediation removes the redundant desktop Gresham Blog, Oregon City, Salem, and duplicate Ask ATM AI controls. It preserves ATM Expert AI, Call/Text 24/7, Check Location, mobile Ask ATM AI, and the regional guide content/routes elsewhere in the application.

Base44 checkpoint: `6aa59c476b8206a4282af729`.
Base44 commit: `ecb525720a35e559449c577ee0856931ff84e582`.

## Experiment 2: hero explanation

A separate checkpoint compresses the hero explanation so the primary offer is encountered sooner while retaining the operational and written-agreement qualifications.

Base44 checkpoint: `6aa5efd2334bf147fd4a624f`.
Base44 commit: `c83c88c8545c460cd679724c27ffa7409dc15f2c`.
Build and lint passed.

## Why this is useful

The interesting capability is not merely scoring a screen. AML provides an inspectable path from an explicit human judgment to a deterministic rendering decision and then to a narrowly scoped UI remediation. In this experiment, suppression means reducing redundant presentation, not deleting useful capability.

That suggests an auditable attention-governance workflow: capture the real interface, hash the evidence, label specific targets with provenance, apply one deterministic rule, record the decisions, make the smallest remediation, recapture production, and reproduce the receipt.

## Evidence boundary

The attention_cost and restoration_value values are declared subjective operator-review labels. They are not objective measurements of human attention, physiological measurements, independent validation, or proof of improved conversion, usability, accessibility, or business performance.

The existing receipt is intentionally `real_screen_evidence_eligible: false`.

An exact post-publish 1363 x 936 production capture has not yet been collected in the connected execution environment. Therefore this report does not claim that either remediation is production-verified. Production verification requires a new exact capture, hashes, explicit label provenance, two deterministic harness runs, and byte-for-byte receipt comparison.

That boundary is important to the AML approach: code changes, deterministic receipts, and production observations are separate pieces of evidence and should not be represented as interchangeable.

## Before evidence

Screenshot SHA-256: `4f9a4c64a11b28911029fb2f879e7145078059cfdd40e6e5fa1f571d0b57999e`
Rendered HTML SHA-256: `13fd331d96060d63fed9e1e68421d496423e3a6802fa2d48775c9b0e99338599`
DOM SHA-256: `c815522691b7467dc25eab6cf0b13a8c6717c9211a05d7931ead6a408c4e541f`
Semantic screen SHA-256: `d780c25bee4162c4206091aaca640b2197f2d9f414b41223196bc0a6adeb0ba9`

## Next verification gate

Experiment 1 should be considered verified only when a post-publish capture confirms that the redundant desktop controls are absent and the retained destinations/actions remain accessible. Experiment 2 should receive its own after-capture before any outcome claim is made.

The strength of this experiment is reproducibility and evidence discipline: a small rule can produce a reviewable decision trail without pretending subjective labels are objective science.
