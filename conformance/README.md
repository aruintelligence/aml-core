# ĀML Conformance

ĀML conformance is designed around a simple principle:

> A claim about ĀML behavior should be independently reproducible from a published contract and published vectors.

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## Current level

| Level | Protocol | Scope | Status |
|---|---|---|---|
| Decision Core 1 | `aml-conformance/decision-core-1` | deterministic ALLOW/SUPPRESS decision rule | experimental |

Decision Core 1 is intentionally small. It gives implementers a first target that does not require the reference parser, runtime, package, browser layer, receipt stack, or trust system.

## Run the independent verifier

From the repository root:

```bash
python3 conformance/independent-python/verify.py
```

The verifier uses only the Python standard library and does not import the ĀML JavaScript runtime.

## Implement it yourself

1. Read [`../CONFORMANCE.md`](../CONFORMANCE.md).
2. Load [`decision-core-1.json`](decision-core-1.json).
3. Implement the published rule directly.
4. Require every vector to match.
5. Publish an implementation declaration using [`implementation-declaration.schema.json`](implementation-declaration.schema.json).
6. State the exact protocol identifier you pass; do not claim broader ĀML conformance.

## Why levels are narrow

ĀML contains multiple separable surfaces: syntax, meaning trees, policy evaluation, accessibility and consent controls, evidence, receipts, canonicalization, signatures, wire envelopes, federation, and trust.

A single vague "ĀML compatible" label would hide too much. Versioned levels let an implementation say exactly what has been reproduced and tested.

## Conformance language

Acceptable experimental wording:

- `Passes aml-conformance/decision-core-1`
- `Independent implementation of ĀML Decision Core 1`
- `Tested against the published Decision Core 1 vectors`

Avoid wording that implies standards-body approval, security certification, accessibility certification, or endorsement by ĀRU Intelligence Inc.™ unless a separate written program explicitly grants it.

## Roadmap

Candidate future levels:

- **AMT Canonical 1** — canonical meaning-tree representation
- **Policy Envelope 1** — interoperable policy decision envelopes
- **Semantic Diff 1** — golden semantic-diff and risk vectors
- **Receipt Material 1** — deterministic receipt signing material
- **Wire 1** — canonical `aml-wire/1` envelopes and protocol vectors

A candidate becomes a conformance level only when its normative behavior and vectors are precise enough for independent implementations to agree without importing the reference runtime.
