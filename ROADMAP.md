# ĀML™ Development Roadmap

ĀML™ is an experimental meaning-native, policy-aware execution layer for accountable human-facing interfaces.

## Current status — v1.2.0

Implemented today:

- `.aml` lexer and parser
- Abstract Syntax Tree generation
- Abstract Meaning Tree generation
- browser-compatible rendering
- pluggable policy engines
- composed policy profiles
- counterfactual policy simulation
- deterministic machine intent → ĀML generation
- consent-aware policy evaluation
- privacy-aware policy evaluation
- session attention budgets
- accountable execution receipts
- SHA-256 build and receipt integrity
- Ed25519 build and receipt attestations
- semantic diagnostics
- CLI inspection, lint, validation, explanation, simulation, verification and signing
- browser playground
- Node/browser parity testing
- VS Code language definition
- dependency-free language server
- machine-readable schemas and capability manifests
- automated conformance fixtures
- GitHub Actions CI and release publishing
- local Markdown link integrity checks

Published release: [v1.2.0](https://github.com/aruintelligence/aml-core/releases/tag/v1.2.0)

## Near-term priorities — v1.3

### Policy composition

- signed policy packs
- policy-pack schemas
- explicit policy precedence
- conflict-resolution rules
- user-owned policy profile files
- organization policy packs
- policy version pinning

### Semantic and policy diffs

- `aml diff` for meaning-bearing source changes
- decision diffs between two compiler runs
- policy diffs explaining why outcomes changed
- receipt comparisons across versions

### Accessibility policies

- reduced-motion context
- high-contrast preferences
- cognitive-load preferences
- screen-reader-oriented semantics
- keyboard-navigation policy inputs

### Runtime audit streams

- append-only decision events
- cumulative session attention accounting
- consent grant/revocation events
- receipt chaining
- replayable audit histories

### Developer tooling

- editor client integration for `aml-lsp`
- richer completion context
- definition/reference support
- structured code actions
- canonical formatter that preserves comments
- stronger malformed-input diagnostics

## Medium-term priorities — v1.4+

### AI accountability

- AI proposal receipts distinct from final execution receipts
- provenance metadata for generated intent
- multiple proposed UI alternatives before policy selection
- explainable fallback generation when a policy suppresses content
- adversarial intent and policy fuzzing

### Policy research infrastructure

- richer conformance suites
- policy benchmark fixtures
- deterministic policy replay
- policy test vectors
- comparative evaluation harnesses
- empirical-model plug-in boundary

### Privacy and data governance

- declared data categories
- retention-purpose declarations
- data-minimization policies
- third-party transfer declarations
- runtime privacy-budget experiments

## v2 research direction

The long-term question is whether the Abstract Meaning Tree can become an executable semantic substrate rather than only a compilation intermediate.

Potential v2 directions:

- executable AMT graph traversal
- semantic-first runtime scheduling
- meaning-aware component negotiation
- user-controlled policy runtimes
- context-aware adaptive rendering
- semantic continuity across sessions
- accountable multi-agent interface generation

## Evidence boundary

Roadmap items are research targets, not guarantees. Current ĀML policies do not establish scientifically validated universal measures of ethics, attention, restoration, privacy, accessibility, or wellbeing.

The project goal is to make assumptions and decisions **explicit, testable, replaceable, reproducible, and attestable**.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
