# ĀML Witness Kit

**Status: SHIPPED**

This kit is for independent reproduction. Do not report a successful reproduction unless you actually ran it.

## Browser reproduction

1. Open https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1
2. Confirm the decision is `SUPPRESS`.
3. Change `restoration_value` to `5`.
4. Confirm the decision becomes `ALLOW`.
5. Copy the exact proof URL.

## Local deterministic replay

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
node demos/undeniable-proof/replay-proof.mjs
node scripts/check-flood-fixtures.js
```

## Report template

```text
Environment:
Browser / Node version:
Artifact tested:
Input URL or fixture:
Expected result:
Observed result:
Reproduced: yes / no / partial
Screenshot or log:
Notes:
```

## What counts as a useful witness

- expected result reproduced
- different result observed
- setup failed with a reproducible error
- spec ambiguity found
- browser/runtime mismatch found

A negative result is useful evidence. Leave `WITNESSES.md` empty rather than inventing external validation.

**Witness ask:** open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
