# ĀML™ Changelog

All notable changes to ĀML™ — ĀRU Meaning Language™ — are documented here.

## [Unreleased]

### Next

- accessibility-first policy packs and runtime preferences
- signed policy-pack distribution and trust chains
- semantic and policy diffs between AML revisions
- policy conflict-resolution strategies beyond `all_must_allow`
- runtime audit streams and cumulative session accounting
- adversarial policy fuzzing and independent empirical evaluation

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
- Added `restorative_v1` and `attention_conservative_v1` built-in policy engines.
- Added `consent_guard_v1` for runtime consent-aware rendering.
- Added `privacy_guard_v1` for personal-data collection declarations and runtime privacy consent.
- Added `session_attention_budget_v1` for runtime attention-budget enforcement.
- Preserved the semantic distinction between an omitted policy value and an explicitly declared zero.

### Policy composition and profiles

- Added `composePolicies()` for multi-policy evaluation.
- Added `policyFromProfile()` for profile-driven policy execution.
- Added built-in policy profiles: `calm_default`, `strict_attention`, and `privacy_first`.
- Added counterfactual policy simulation so the same semantic source can be evaluated under multiple policy regimes before one composed result is selected.
- Runtime context is now propagated through policy simulation and final compilation.

### AI-native source generation

- Added deterministic `generateAMLFromIntent()` translation from constrained machine-readable intent JSON into AML source.
- Invalid identifiers are rejected before AML source emission.
- Generated AML passes through the same compiler, meaning tree, policy, and accountability pipeline as human-authored AML.

### Cryptographic integrity

- Added detached Ed25519 build-manifest attestations with embedded public-key fingerprints.
- Added build-attestation verification and tamper tests.
- Policy identity and policy rationale are now recorded in render decisions.
- Build manifests record the policy that produced the compiled bundle.

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

These extend the existing `compile`, `validate`, `inspect`, `explain`, `lint`, and `verify` commands.

### Protocols and documentation

- Added the Accountable AI Execution Pipeline protocol documentation.
- Added Policy Profiles documentation.
- Added `schema/execution-receipt.schema.json`.
- Expanded `AML_CAPABILITIES.json` to describe the v1.2 policy, privacy, receipt, signature, and accountable-execution surface.
- Rebuilt the README around the v1.2 accountable execution architecture.

### Verification

- Added automated tests for policy profiles and policy composition.
- Added privacy-policy tests.
- Added session-attention-budget tests.
- Added end-to-end execution receipt tests.
- Added signed execution receipt tests.
- Added counterfactual policy tests.
- CI continues to verify compiler/browser parity, conformance fixtures, language-server behavior, build integrity, benchmarks, semantic diagnostics, and the expanded execution layer.

## [1.1.0] — 2026-09-07

### Compiler

- Added `compileSource(source, options)` for pure in-memory AML compilation without filesystem output.
- Preserved `compileAML(inputPath, outputDir, options)` as the artifact-emitting filesystem compiler.
- Added deterministic decision timestamps for reproducible compilation.
- Added comparison-operator lexing and structured single-binary-comparison parsing for `>`, `>=`, `<`, `<=`, `=`, `==`, and `!=`.
- Added SHA-256 `build_manifest.json` output binding source and emitted artifacts.
- Added active `verifyBuildManifest()` integrity verification and post-build tamper detection.

### Public JavaScript API

- Exported `compileAML`, `compileSource`, `ethicalRenderGate`, `analyzeAMT`, `explainCompilation`, and `verifyBuildManifest`.
- Added dependency-free language-intelligence APIs: `getCompletionItems`, `getHoverInfo`, and `getLanguageCatalog`.

### CLI

- Added `aml validate <file.aml>` for parse/evaluation checks without writing artifacts.
- Added `aml inspect <file.aml>` to emit the Abstract Meaning Tree and raw render decisions as JSON.
- Added `aml explain <file.aml>` for compact decision explanations and diagnostic summaries.
- Added `aml lint <file.aml>` for semantic diagnostics.
- Added `aml verify <build_manifest.json>` for SHA-256 bundle verification.

### Semantic diagnostics

- Added compiler-backed semantic diagnostics with codes `AML001`–`AML005`.
- Added `AML_PARSE` diagnostics in the language-server layer for invalid source.

### Browser runtime and tooling

- Added a dependency-free browser AML compiler and interactive source playground.
- Added automated browser/core parity tests.
- Added VS Code `.aml` language registration and syntax highlighting.
- Added a shared language-intelligence catalog.
- Added the dependency-free `aml-lsp` stdio Language Server Protocol implementation.
- Added benchmark, conformance, replication, and build-integrity protocols.

### Capability discovery

- Added `AML_CAPABILITIES.json` and automated capability-reference tests.

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
