# ĀML™ Testing Specification

## Current verification model — v1.2.0

ĀML testing covers more than parser correctness. The project now verifies syntax, semantics, policy behavior, reproducibility, integrity, tooling, browser parity, and accountable execution receipts.

## Core automated verification

The repository's CI currently checks:

- local Markdown link integrity
- unit and integration tests
- CLI compilation
- filesystem artifact emission
- SHA-256 build-manifest verification
- in-memory validation
- semantic linting
- explanation output
- inspectable decision output
- benchmark harness execution

## Compiler tests

Compiler tests should verify:

- tokenization
- parsing
- AST shape
- Abstract Meaning Tree construction
- declared-value preservation
- deterministic source compilation
- malformed-input handling
- comparison-expression handling
- output artifact generation

## Policy tests

Policy tests should verify both positive and negative outcomes.

Current built-in policy families include:

- `restorative_v1`
- `attention_conservative_v1`
- `consent_guard_v1`
- `privacy_guard_v1`
- `session_attention_budget_v1`

Tests should preserve the distinction between a missing value and an explicitly declared zero value.

## Conformance fixtures

Canonical fixtures live under [`conformance/`](conformance/).

- [`conformance/allow.aml`](conformance/allow.aml) — expected baseline allow case
- [`conformance/suppress.aml`](conformance/suppress.aml) — expected baseline suppress case
- [`conformance/manifest.json`](conformance/manifest.json) — executable fixture inventory
- [`CONFORMANCE.json`](CONFORMANCE.json) — public compatibility manifest

A second implementation should be able to use these fixtures to compare observable behavior.

## Browser parity

The dependency-free browser compiler is tested against the Node compiler on representative examples and conformance fixtures.

Parity tests should compare semantic structures and policy decisions rather than only final HTML.

## Accountable execution tests

The v1.2 pipeline should test:

```text
machine intent
  ↓
ĀML source
  ↓
policy simulations
  ↓
selected profile decisions
  ↓
render output
  ↓
execution receipt
```

Tests should verify that the receipt binds the original intent, generated source, simulation data, final decisions, and output hashes.

## Integrity and tamper tests

Integrity testing includes deliberate mutation.

A valid bundle or receipt should verify before mutation. A modified artifact, manifest, or signed receipt should fail the appropriate verification path afterward.

Current integrity mechanisms include:

- SHA-256 build manifests
- execution-receipt hashes
- Ed25519 build attestations
- Ed25519 execution-receipt attestations

Cryptographic verification proves consistency with a key/signature and recorded bytes. It does not prove that the policy itself is correct or that a signer is trustworthy.

## Documentation integrity

Local Markdown links are checked automatically. A documentation change that introduces a missing relative path should fail CI.

This protects the public proof surface from silent GitHub 404s.

## Benchmarking

Performance measurements should follow [`docs/BENCHMARKING.md`](docs/BENCHMARKING.md).

Benchmark output is useful for regression detection, but benchmark numbers should not be presented as universal performance claims without recording environment, version, workload, and iteration count.

## Replication

Independent replication guidance is maintained in [`REPLICATION.md`](REPLICATION.md).

A replication report should include:

- exact release tag or commit SHA
- Node.js version
- operating system
- commands executed
- fixture inputs
- observed policy decisions
- verification results
- deviations, if any

## Evidence boundary

Passing tests establish behavior for the tested implementation and inputs. They do not establish that current attention/restoration scores are scientifically validated, that a policy is universally ethical, or that generated intent is truthful.

ĀML's testing objective is narrower and concrete: make implementation behavior **observable, reproducible, challengeable, and difficult to silently alter**.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
