# ĀML Compatible — Conformance Badge

A project should not claim **ĀML Compatible** merely because it uses AML terminology. The badge is intended to mean that an implementation passes a published machine-verifiable compatibility suite.

## Reference badge

```md
[![ĀML Compatible](https://img.shields.io/badge/%C4%80ML-Compatible-34d399?style=for-the-badge&labelColor=07111f)](https://github.com/aruintelligence/aml-core/actions/workflows/conformance.yml)
```

## Minimum compatibility requirements

A candidate implementation should:

1. parse the canonical fixture inventory;
2. produce a structured syntax representation;
3. produce an Abstract Meaning Tree or explicitly equivalent semantic representation;
4. emit machine-readable render decisions;
5. preserve canonical allow/suppress behavior where the profile/policy is defined by the conformance suite;
6. expose the implementation/version being tested;
7. document material deviations rather than silently calling them compatible.

## Reference implementation check

The `AML Conformance` GitHub Actions workflow runs:

```bash
node scripts/check-conformance.js
```

against `conformance/manifest.json`.

Passing the reference suite proves compatibility with those published software fixtures. It does **not** certify ethical correctness, accessibility compliance, security, human wellbeing, or regulatory compliance.

## Future

The conformance suite should evolve toward versioned normative fixtures so independent implementations in other languages can test against the same input/output expectations.