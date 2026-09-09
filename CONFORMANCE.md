# ĀML Conformance Contract

Status: experimental conformance contract for the ĀML reference project.

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## Why this exists

A language becomes more credible when its behavior can be reproduced without trusting its reference implementation.

This document defines a deliberately small, implementation-independent conformance target for ĀML decision semantics. It is not a standards-body certification program and passing it does not grant an official or certified mark.

## Conformance level: Decision Core 1

An implementation conforms to **ĀML Decision Core 1** when it can consume each vector in `conformance/decision-core-1.json`, independently compute the render decision, and produce the expected result for every vector.

The normative decision rule for this level is:

```text
render_allowed = restoration_value >= attention_cost
```

Inputs are declared/model values. Decision Core 1 makes no claim that either score objectively measures human cognition, wellbeing, value, or harm.

### Required behavior

For every vector an implementation MUST:

1. read `attention_cost` and `restoration_value` as finite JSON numbers;
2. compute `restoration_value >= attention_cost` without hidden state;
3. emit `ALLOW` when the expression is true;
4. emit `SUPPRESS` when the expression is false;
5. produce the same result on repeated evaluation of the same vector.

An implementation MUST NOT silently reinterpret the scores using an undocumented weighting function and still claim Decision Core 1 conformance.

## Independence requirement

A useful independent implementation SHOULD implement the rule from this document and vectors directly rather than importing the ĀML reference runtime. This makes the suite a cross-implementation test rather than a wrapper test.

## Vector format

`conformance/decision-core-1.json` is a JSON object containing:

- `protocol`: conformance protocol identifier;
- `rule`: human-readable normative rule;
- `vectors`: ordered test cases;
- each case has an `id`, declared inputs, and `expected_decision`.

The vector IDs are stable within Decision Core 1. New vectors may be appended without changing the decision rule. A rule change requires a new conformance level/protocol identifier.

## Passing

A runner passes only when **every** vector matches. Partial success is diagnostic, not conformance.

## Reference-independent example

`conformance/independent-python/verify.py` is intentionally tiny and uses only the Python standard library. It does not import the JavaScript ĀML runtime. Its purpose is to demonstrate that the decision contract can be reproduced from the published semantics alone.

Run from the repository root:

```bash
python3 conformance/independent-python/verify.py
```

A successful run prints a PASS line and exits `0`. A mismatch prints failures and exits non-zero.

## What this does not prove

Decision Core 1 does not prove conformance for parsing, AST/AMT construction, policy packs, consent, privacy, accessibility, signatures, receipts, federation, trust delegation, browser bridges, HTTP services, or any other broader ĀML capability. Those require their own versioned conformance levels.

That narrowness is intentional: the first independent target should be small enough to implement correctly in an afternoon and precise enough that two implementations cannot disagree about what passing means.

## Next conformance levels

Planned candidates include canonical AMT serialization, policy decision envelopes, deterministic receipt material, semantic-diff vectors, and wire-protocol golden vectors. Each should remain separately testable so implementations can state exactly what they support.
