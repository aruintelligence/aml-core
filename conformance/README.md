# ĀML Conformance

ĀML conformance is designed around a simple principle:

> A claim about ĀML behavior should be independently reproducible from a published contract and published vectors.

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## Current levels

| Level | Protocol | Scope | Status |
|---|---|---|---|
| Decision Core 1 | `aml-conformance/decision-core-1` | deterministic ALLOW/SUPPRESS decision rule | experimental |
| Sorted JSON 1 | `aml-conformance/sorted-json-1` | exact `sorted-json-v1` byte serialization + SHA-256 for the published vector domain | experimental |

Decision Core 1 is intentionally small. It gives implementers a first target that does not require the reference parser, runtime, package, browser layer, receipt stack, or trust system.

Sorted JSON 1 is also deliberately narrow. It is not a claim to define general JSON canonicalization; it freezes only the behavior explicitly covered by the published vectors. See [`SORTED_JSON_1.md`](SORTED_JSON_1.md).

## Run the independent verifiers

From the repository root:

```bash
python3 conformance/independent-python/verify.py
node conformance/independent-javascript/verify.mjs
python3 independent/python/check_canonical_vectors.py
node conformance/independent-javascript/verify_canonical_json.mjs
```

These checks do not import the ĀML reference runtime for the behavior they reproduce.

## Test an external implementation as a black box

Implement the stdin/stdout contract in [`BLACK_BOX_PROTOCOL.md`](BLACK_BOX_PROTOCOL.md), then point the generic runner at your Decision Core 1 executable:

```bash
node conformance/run-external.mjs -- python3 my_aml_decision_core.py
```

The runner feeds published valid and must-reject vectors to the process and grades only observable behavior. Your implementation can be written in any language.

## Implement it yourself

1. Read [`../CONFORMANCE.md`](../CONFORMANCE.md).
2. Choose an exact protocol identifier from [`manifest.json`](manifest.json).
3. Read that protocol's normative document and published vectors.
4. Implement the published behavior directly.
5. Require every applicable positive and negative vector to pass.
6. Optionally expose the Decision Core black-box executable protocol.
7. Publish an implementation declaration using [`implementation-declaration.schema.json`](implementation-declaration.schema.json).
8. State only the exact protocol identifier you pass; do not claim broader ĀML conformance.

## Why levels are narrow

ĀML contains multiple separable surfaces: syntax, meaning trees, policy evaluation, accessibility and consent controls, evidence, receipts, canonicalization, signatures, wire envelopes, federation, and trust.

A single vague "ĀML compatible" label would hide too much. Versioned levels let an implementation say exactly what has been reproduced and tested.

## Conformance language

Acceptable experimental wording:

- `Passes aml-conformance/decision-core-1`
- `Passes aml-conformance/sorted-json-1`
- `Independent implementation of ĀML Decision Core 1`
- `Tested against the published Sorted JSON 1 vectors`

Avoid wording that implies standards-body approval, security certification, accessibility certification, general JSON-standard equivalence, or endorsement by ĀRU Intelligence Inc.™ unless a separate written program explicitly grants it.

## Registry integrity

`conformance/manifest.json` is the machine-readable protocol catalog. CI checks that protocol identifiers agree with the implementation declaration schema and GitHub submission form, and that referenced normative documents, vectors, and independent examples actually exist.

## Roadmap

Candidate future levels:

- **AMT Canonical 1** — canonical meaning-tree representation
- **Policy Envelope 1** — interoperable policy decision envelopes
- **Semantic Diff 1** — golden semantic-diff and risk vectors
- **Receipt Material 1** — deterministic receipt signing material
- **Wire 1** — canonical `aml-wire/1` envelopes and protocol vectors

A candidate becomes a conformance level only when its normative behavior and vectors are precise enough for independent implementations to agree without importing the reference runtime.
