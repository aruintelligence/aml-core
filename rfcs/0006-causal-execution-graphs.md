# RFC 0006 — Causal Execution Graphs

Status: Draft

## Summary

Modern agentic systems rarely make isolated decisions. A rendered interface may depend on a user request, a policy evaluation, an accessibility audit, a consent state, prior agent work, and output from another service.

ĀML should preserve that causal structure instead of reducing it to one opaque log entry.

## Model

A causal event contains:

- protocol identifier;
- event kind;
- sorted parent event hashes;
- canonical payload;
- SHA-256 event hash.

A causal execution graph is a directed acyclic graph of those events.

Events may have zero, one, or many parents. Multi-parent events let a render decision explicitly bind several prior evaluations.

## Verification

A verifier checks:

1. each event hash matches its canonical event body;
2. every referenced parent exists;
3. the graph contains no cycles.

The reference implementation also exposes graph roots and heads.

## Intended uses

- multi-agent execution lineage;
- cross-service accountability;
- policy + accessibility + consent convergence;
- explaining which prior decisions caused a render;
- preserving dependency history across federated AML runtimes.

## Non-claims

A valid causal graph proves structural integrity of declared dependencies. It does not prove the declared causal relationship is truthful, sufficient, or scientifically causal.

## Reference implementation

`runtime/causalExecutionGraph.js`
