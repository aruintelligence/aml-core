# ĀML Conformance Contract

Status: experimental conformance contract for the ĀML reference project.

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## Why this exists

A language becomes more credible when its behavior can be reproduced without trusting its reference implementation.

This document defines a deliberately small, implementation-independent conformance target for ĀML decision semantics. It is not a standards-body certification program and passing it does not grant an official or certified mark.

## Conformance level: Decision Core 1

An implementation conforms to **ĀML Decision Core 1** when it can consume each positive vector in `conformance/decision-core-1.json`, independently compute the render decision, produce the expected result for every vector, and reject every invalid input in `conformance/decision-core-1-invalid.json`.

The normative decision rule for this level is:

```text
render_allowed = restoration_value >= attention_cost
```

Inputs are declared/model values. Decision Core 1 makes no claim that either score objectively measures human cognition, wellbeing, value, or harm.

### Required behavior

For every valid vector an implementation MUST:

1. read `attention_cost` and `restoration_value` as finite JSON numbers;
2. compute `restoration_value >= attention_cost` without hidden state;
3. emit `ALLOW` when the expression is true;
4. emit `SUPPRESS` when the expression is false;
5. produce the same result on repeated evaluation of the same vector.

For every must-reject vector an implementation MUST reject the input rather than coercing it into a score. In particular, booleans, strings, nulls, and missing score fields are not valid Decision Core 1 inputs.

An implementation MUST NOT silently reinterpret the scores using an undocumented weighting function or type-coercion rule and still claim Decision Core 1 conformance.

## Independence requirement

A useful independent implementation SHOULD implement the rule from this document and vectors directly rather than importing the ĀML reference runtime. This makes the suite a cross-implementation test rather than a wrapper test.

## Vector format

`conformance/decision-core-1.json` contains valid decision vectors:

- `protocol`: conformance protocol identifier;
- `rule`: human-readable normative rule;
- `vectors`: ordered test cases;
- each case has an `id`, declared inputs, and `expected_decision`.

`conformance/decision-core-1-invalid.json` contains inputs that MUST be rejected.

Vector IDs are stable within Decision Core 1. New vectors may be appended when they do not change the normative rule. A rule or accepted-input-domain change requires a new conformance level/protocol identifier.

## Passing

A runner passes only when **every valid vector matches and every must-reject vector is rejected**. Partial success is diagnostic, not conformance.

## Reference-independent examples

Two intentionally small examples ship with the repository:

- `conformance/independent-python/verify.py` — Python standard library only;
- `conformance/independent-javascript/verify.mjs` — Node.js built-ins only.

Neither imports the ĀML reference runtime. Their purpose is to demonstrate that the decision contract can be reproduced from the published semantics alone.

Run from the repository root:

```bash
python3 conformance/independent-python/verify.py
node conformance/independent-javascript/verify.mjs
```

Both implementations are required by CI to emit the same PASS result.

## Machine-readable declaration

Implementers can describe an independently tested implementation using `conformance/implementation-declaration.schema.json`. A declaration identifies the exact protocol, implementation/version, language, source location, vector commit, and PASS/FAIL result.

Self-declaration is evidence of a test result, not certification or endorsement.

## What this does not prove

Decision Core 1 does not prove conformance for parsing, AST/AMT construction, policy packs, consent, privacy, accessibility, signatures, receipts, federation, trust delegation, browser bridges, HTTP services, or any other broader ĀML capability. Those require their own versioned conformance levels.

That narrowness is intentional: the first independent target should be small enough to implement correctly in an afternoon and precise enough that two implementations cannot disagree about what passing means.

## Next conformance levels

Planned candidates include canonical AMT serialization, policy decision envelopes, deterministic receipt material, semantic-diff vectors, and wire-protocol golden vectors. Each should remain separately testable so implementations can state exactly what they support.
