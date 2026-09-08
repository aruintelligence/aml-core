# ĀML Core v1.3.0 — Trust, Difference, Accessibility, and Runtime Accountability

ĀML v1.3.0 extends Accountable AI Execution with six new system-level capabilities:

- signed policy packs
- semantic diffs
- policy diffs
- hash-chained runtime audit streams
- executable accessibility policies
- cumulative attention accounting

## Signed policy packs

Policy packs are data-only compositions of installed policy IDs. They can be canonically hashed, signed with Ed25519, and independently verified. The design intentionally does not allow a signed policy pack to smuggle executable JavaScript.

## Semantic diffs

`aml semantic-diff` compares Abstract Meaning Trees and reports added, removed, changed, and unchanged meaning-bearing nodes, separating structural, property, and meaning-metadata changes.

## Policy diffs

`aml policy-diff` runs identical source/context through two policies or policy profiles and reports the exact render decisions whose outcome or rationale changed.

## Runtime audit streams

ĀML now provides append-only SHA-256 hash-chained audit streams. Each runtime event commits to the previous event hash, making mutation detectable.

Accountable execution receipts can bind the audit stream and its verification result.

## Cumulative attention accounting

The new Attention Ledger tracks attention across a session rather than treating every node independently. Once earlier rendered components consume the budget, later components can be suppressed by cumulative enforcement.

Accountable execution regenerates final HTML from the cumulative-enforced decision set.

## Accessibility policies

New policies:

- `reduced_motion_v1`
- `contrast_safety_v1`
- `cognitive_load_guard_v1`

New profiles:

- `accessibility_first`
- `human_first`

These mechanisms are an executable policy layer and do not claim to replace WCAG conformance or assistive-technology testing.

## New CLI surface

```text
aml semantic-diff
aml policy-diff
aml sign-policy-pack
aml verify-policy-pack
aml verify-audit
aml attention-account
```

These join the existing compiler, accountable execution, receipt signing, conformance, integrity, diagnostics, language-server, and browser tooling.

## Repository reliability

v1.3 also adds a local Markdown link-integrity gate to CI. Broken relative repository links now fail the build instead of silently producing public GitHub 404s.

Compatibility paths were restored for:

- `REPLICATION.md`
- `CONFORMANCE.json`
- `docs/API.md`

## Verify

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
npm run check:links
npm test
node bin/aml.js version
node bin/aml.js policies
node bin/aml.js profiles
```

Browser playground:

https://aruintelligence.github.io/aml-core/playground.html

Live lab:

https://aruintelligence.github.io/aml-core/

## Evidence boundary

ĀML v1.3 improves policy transparency, integrity, runtime accountability, accessibility-aware decision inputs, and cumulative accounting. It does not establish that any current policy is universally ethical, that attention/restoration scores are validated human measurements, or that a signature proves an issuer is trustworthy.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**

Code is MIT licensed. Claimed marks remain separate from the code license.
