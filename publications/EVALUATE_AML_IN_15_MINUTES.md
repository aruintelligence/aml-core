# Evaluate ĀML in 15 Minutes

**Status: SHIPPED evaluation path**

This is for skeptical developers, product leaders, security teams, researchers, and technical buyers.

## Minute 0–2 — See the decision

Open:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

Observe **SUPPRESS**. Change `restoration_value` to `5`. Observe **ALLOW**.

## Minute 2–5 — Inspect the declaration

Read the AML shown by the proof. Ask whether the declared purpose and declared scores are understandable enough to review.

## Minute 5–8 — Reproduce the receipt

Run:

```bash
npm install --ignore-scripts
node demos/undeniable-proof/replay-proof.mjs
```

The important question is not whether you agree with the policy. It is whether the execution can be reproduced and inspected.

## Minute 8–11 — Try tampering

Open:

https://aruintelligence.github.io/aml-core/browser-evidence-demo.html

Verify the current evidence, then tamper with a copy and verify again.

## Minute 11–13 — Verify outside the page

Use:

https://aruintelligence.github.io/aml-core/detached-verifier.html

or the Python/Go reference verifier paths under `independent/`.

## Minute 13–15 — Decide whether to keep testing

Three useful outcomes are all acceptable:

- **Continue** — the boundary appears useful enough for a pilot.
- **Disagree** — the policy/model does not fit your needs; publish why.
- **Break it** — a proof, verifier, or contract fails; file the reproduction.

Before repeating broad claims, read `CLAIMS.md`.
