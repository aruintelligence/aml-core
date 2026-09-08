# ĀML™ Changelog

All notable changes to ĀML™ — ĀRU Meaning Language™ — are documented here.

## [Unreleased]

### Next

- policy conflict-resolution strategies beyond `all_must_allow`
- signed policy trust chains and delegated issuers
- accessibility conformance research beyond the current policy layer
- adversarial policy fuzzing
- runtime stream persistence and cross-session analysis
- independent empirical evaluation of attention/restoration models

## [1.3.0] — 2026-09-07

### Signed policy packs

- Added data-only ĀML policy packs that reference installed policy IDs without embedding executable JavaScript.
- Added canonical policy-pack hashing.
- Added Ed25519 policy-pack signing and verification.
- Added public-key fingerprint validation and mutation detection.
- Added CLI commands `sign-policy-pack` and `verify-policy-pack`.

### Semantic and policy diffs

- Added `semanticDiff()` to compare compiled Abstract Meaning Trees rather than raw lines of source.
- Semantic diffs classify added, removed, changed, and unchanged meaning-bearing nodes.
- Added `policyDiff()` to hold source/context constant while comparing policy or profile outcomes.
- Added CLI commands `semantic-diff` and `policy-diff`.

### Runtime audit streams

- Added append-only SHA-256 hash-chained runtime audit streams.
- Each entry commits to its payload and previous-entry hash.
- Added verification that detects sequence, previous-hash, or payload mutation.
- Accountable execution now binds the runtime audit stream into the execution receipt.
- Added `verify-audit` CLI support.

### Cumulative attention accounting

- Added the ĀML Attention Ledger for session-level attention accounting.
- Added cumulative budget consumption across multiple render decisions.
- Added enforcement that can suppress a later node after earlier allowed nodes consume the remaining session budget.
- Accountable execution regenerates final HTML from cumulative-enforced decisions.
- Added attention-ledger hashes to execution receipts.
- Added `attention-account` CLI support.

### Accessibility policy layer

Added executable runtime policies:

- `reduced_motion_v1`
- `contrast_safety_v1`
- `cognitive_load_guard_v1`

Added policy profiles:

- `accessibility_first`
- `human_first`

The accessibility layer is explicitly supplemental and does not claim to replace WCAG conformance or assistive-technology testing.

### Accountable execution receipts

- Execution Receipt protocol advanced to v1.1.
- Receipts can now bind runtime audit streams and attention ledgers.
- Receipt verification checks the receipt hash, audit-chain integrity, and ledger hash together.

### Repository reliability

- Restored public compatibility paths for `REPLICATION.md`, `CONFORMANCE.json`, and `docs/API.md`.
- Added an automated local Markdown link checker.
- CI now fails when a relative documentation link points to a missing repository path.

### Public API + CLI

Added exported APIs for:

- signed policy packs
- semantic diffs
- policy diffs
- runtime audit streams
- attention ledgers
- cumulative attention enforcement

Added CLI commands:

```text
aml semantic-diff
aml policy-diff
aml sign-policy-pack
aml verify-policy-pack
aml verify-audit
aml attention-account
```

### Verification

- Added policy-pack signature and tamper tests.
- Added semantic-diff tests.
- Added policy-diff tests.
- Added runtime audit-stream mutation tests.
- Added cumulative attention-accounting tests.
- Added reduced-motion accessibility-policy tests.
- Updated machine-readable capability tests for v1.3.

## [1.2.0] — 2026-09-07

### Accountable AI execution

- Added `executeAccountableIntent()` for the full machine intent → ĀML → policy simulation → composed policy → browser output pipeline.
- Added `ĀML Accountable Execution Receipt` objects binding original intent, generated AML, runtime context, policy simulations, selected decisions, and final output.
- Added SHA-256 hashes for intent, generated AML, policy simulation, render decisions, output, and the receipt itself.
- Added `verifyExecutionReceipt()` mutation detection.
- Added an execution-receipt JSON Schema.

### Signed execution receipts

- Added `signExecutionReceipt()` using Ed25519.
- Added `verifySignedExecutionReceipt()` for receipt integrity, signature verification, and public-key fingerprint validation.
- Added automated tests proving mutation invalidates signed execution receipts.

### Policy engine architecture

- Replaced the single hard-coded policy path with a pluggable policy-engine abstraction.
- Added custom policy-function support.
- Added `restorative_v1`, `attention_conservative_v1`, `consent_guard_v1`, `privacy_guard_v1`, and `session_attention_budget_v1`.
- Preserved the semantic distinction between an omitted policy value and an explicitly declared zero.

### Policy composition and profiles

- Added `composePolicies()` and `policyFromProfile()`.
- Added built-in policy profiles: `calm_default`, `strict_attention`, and `privacy_first`.
- Added counterfactual policy simulation.
- Runtime context is propagated through policy simulation and final compilation.

### AI-native source generation

- Added deterministic `generateAMLFromIntent()` translation from constrained machine-readable intent JSON into AML source.
- Invalid identifiers are rejected before AML source emission.
- Generated AML passes through the same compiler, meaning tree, policy, and accountability pipeline as human-authored AML.

### Cryptographic integrity

- Added detached Ed25519 build-manifest attestations with embedded public-key fingerprints.
- Added build-attestation verification and tamper tests.
- Policy identity and policy rationale are recorded in render decisions.

### CLI

Added:

```text
aml generate
aml execute
aml verify-receipt
aml sign-receipt
aml verify-signed-receipt
aml simulate
aml policies
aml profiles
aml sign
aml verify-attestation
```

## [1.1.0] — 2026-09-07

### Compiler

- Added `compileSource(source, options)` for pure in-memory AML compilation without filesystem output.
- Preserved `compileAML(inputPath, outputDir, options)` as the artifact-emitting filesystem compiler.
- Added deterministic decision timestamps for reproducible compilation.
- Added comparison-operator lexing and structured single-binary-comparison parsing.
- Added SHA-256 `build_manifest.json` output and active bundle verification.

### Tooling

- Added semantic diagnostics, browser compilation/playground, VS Code language registration, a language-intelligence catalog, `aml-lsp`, benchmarks, conformance fixtures, replication protocol, and machine-readable capability discovery.

## [1.0.0] — 2026-05-06

### Initial public architecture draft

- Meaning-native interface philosophy
- EthicalRenderGate™ prototype
- Restoration-oriented rendering
- Coherence-aware runtime concepts
- Accountable rendering systems
- Semantic-first execution philosophy

### Core equation

```text
render_allowed = restoration_value >= attention_cost
```
