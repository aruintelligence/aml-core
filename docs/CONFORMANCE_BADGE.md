# ĀML™ Conformance and Official Compatibility Branding

ĀML intentionally separates **technical conformance** from **official brand certification**.

That distinction allows independent implementations to prove interoperability without automatically receiving a license to present themselves as officially certified, endorsed, sponsored, or controlled by ĀRU Intelligence Inc.™

## 1. Technical conformance — open and reproducible

Any implementation may run the published conformance suite and accurately report its reproducible technical result, subject to applicable law and the non-misleading-use rules in `TRADEMARKS.md`.

Examples of factual statements:

- “Passes the AML v1.3 Core conformance fixtures.”
- “Implements aml-wire/1.0.”
- “Our independent runtime passes the published AML Federated technical tests.”

Technical conformance does **not** by itself mean:

- officially certified by ĀRU;
- endorsed by ĀRU;
- security certified;
- ethically certified;
- accessibility certified;
- regulatory compliant;
- licensed to use official AML badge artwork or commercial certification branding.

## 2. Official ĀML Compatible™ branding — controlled

**ĀML Compatible™**, **ĀML Core Compatible™**, **ĀML Accountable Compatible™**, **ĀML Federated Compatible™**, **ĀML Verifiable Compatible™**, and **ĀML Governed Compatible™** are claimed source-identifying compatibility marks.

Use of official badge artwork or use of these marks in a manner that communicates official certification, authorization, endorsement, partnership, or sponsorship requires written authorization under the current brand policy unless applicable law independently permits the use.

Commercial licensing / official badge requests:

- `COMMERCIAL.md`
- `.github/ISSUE_TEMPLATE/commercial-license.md`
- https://aruintelligence.com/

## Minimum technical compatibility requirements

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

Passing the reference suite proves compatibility with those published software fixtures only. It does **not** prove ethical correctness, accessibility compliance, security, human wellbeing, or regulatory compliance.

## Official badge program

The official badge program may require, depending on the level and commercial use:

- a reproducible conformance artifact;
- identified implementation/version;
- identified language/wire version;
- non-deceptive use of the mark;
- compliance with brand guidelines;
- periodic retesting for evolving versions;
- a written trademark/certification-brand license for official commercial badge use.

Exact commercial terms are set by separate written agreement. Technical interoperability remains testable without buying access to the code.

## Registration status

This document does not claim that the compatibility marks are federally registered certification marks. Do not use ® unless a specific mark is actually registered for the relevant goods/services. See `TRADEMARK_REGISTRATION_PLAN.md`.
