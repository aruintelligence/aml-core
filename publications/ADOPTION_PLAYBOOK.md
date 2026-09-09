# ĀML Adoption Playbook

**Status: DRAFT adoption path built on SHIPPED AML surfaces**

## Stage 1 — Prove one decision

Use the public proof. Change one declared value. Capture the exact URL and receipt.

## Stage 2 — Reproduce locally

Run the deterministic replay and balanced ALLOW/SUPPRESS fixtures.

## Stage 3 — Gate one real UI region

Use `<aml-gate>`, `data-aml-*`, or a page manifest around one bounded interface surface.

## Stage 4 — Define acceptance criteria

Do not ask whether AML is “good.” Ask whether it meets concrete requirements: reviewability, reproducibility, integration effort, evidence quality, performance, and failure behavior.

## Stage 5 — Verify away from the producing page

Use the detached verifier, Python/Go reference verifier, or your own verifier against the immutable snapshot.

## Stage 6 — Invite dissent

Ask somebody outside the implementing team to reproduce or break the result. Preserve negative findings.

## Stage 7 — Decide

Possible outcomes:

- expand the pilot;
- keep AML as a review/testing tool;
- implement a narrower subset;
- reject it with documented evidence.

The playbook is not evidence that any organization has completed these stages.
