# ĀML Research Reproduction Card

**Status: SHIPPED reproduction reference**

## Claim under test

A fixed AML intent can produce a reproducible execution receipt under fixed execution inputs.

## Reference command

```bash
npm install --ignore-scripts
node demos/undeniable-proof/replay-proof.mjs
```

## What to record

- repository commit SHA
- Node version
- operating system
- exact command
- receipt hash
- decision hash
- output hash
- whether the second run matched the first

## Adversarial follow-up

Modify a bound field and verify that the relevant integrity check fails.

## Reporting

A reproduction that disagrees with the expected result is valuable. Publish the environment, exact artifact, and observed difference.

This card tests reproducibility of the reference execution. It does not establish that the policy model is universally correct or that the declared inputs are truthful.
