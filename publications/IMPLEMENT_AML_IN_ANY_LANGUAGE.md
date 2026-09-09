# Implement ĀML in Any Language

## A small challenge with a serious purpose

ĀML should not require trust in one package, one runtime, or one programming language.

The first independent implementation target is deliberately tiny: **ĀML Decision Core 1**.

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## The challenge

Implement this rule in any language:

```text
render_allowed = restoration_value >= attention_cost
```

Then run the published vectors in:

```text
conformance/decision-core-1.json
```

A conforming implementation emits:

- `ALLOW` when restoration value is greater than or equal to attention cost;
- `SUPPRESS` otherwise.

That is the whole first target.

## The catch

Do **not** import the ĀML reference runtime.

Read the contract. Read the vectors. Implement the behavior yourself. If your implementation and the reference project's independent examples agree on every vector, we have evidence that the published semantics are reproducible across implementations.

## Why this matters

A language is more than a repository when another person can implement its semantics from the specification alone.

Independent implementations create pressure in the right direction:

- ambiguous language gets exposed;
- undocumented behavior becomes visible;
- accidental dependency on a reference implementation becomes harder;
- interoperability becomes measurable;
- claims can be tested by critics instead of accepted on authority.

## Start here

1. Read [`../CONFORMANCE.md`](../CONFORMANCE.md).
2. Inspect [`../conformance/decision-core-1.json`](../conformance/decision-core-1.json).
3. Write the rule in Rust, Go, Python, Java, C#, C, Swift, Kotlin, Ruby, PHP, Zig, Elixir, Haskell, Lua, shell, or anything else that can parse the vectors.
4. Require all vectors to pass.
5. Publish the source and the exact vector commit you tested.
6. Use the machine-readable declaration schema if you want to report the result.

## What passing means

Passing means exactly one thing:

> Your implementation reproduces `aml-conformance/decision-core-1` for the published vectors.

It does not mean the implementation is certified, secure, accessible, endorsed, or conformant with the rest of the ĀML architecture.

That precision is a feature, not a limitation.

## Where this goes next

Decision Core 1 is the doorway. Future independent targets can cover canonical meaning trees, semantic diffs, policy envelopes, deterministic receipt material, and wire-level interoperability.

The long-term objective is straightforward:

**No important ĀML behavior should remain credible only because the ĀML repository says it works. Important behavior should be independently reproducible.**
