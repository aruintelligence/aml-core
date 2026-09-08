# ĀML™ Changelog

All notable changes to ĀML™ — ĀRU Meaning Language™ — are documented here.

## [Unreleased]

### Next

- richer semantic policy models
- expanded conformance fixtures
- editor client integration for the stdio language server
- incremental LSP synchronization and workspace intelligence
- independent accessibility and adversarial evaluation
- signed build attestations layered above SHA-256 bundle verification

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
- Removed package scripts that referenced commands not actually implemented.

### Semantic diagnostics

- Added compiler-backed semantic diagnostics with codes `AML001`–`AML005`.
- Detects missing purpose/cost/value metadata and out-of-range v1 policy scores.
- Added `AML_PARSE` diagnostics in the language-server layer for invalid source.

### Browser runtime

- Added a dependency-free browser AML compiler mirroring the Node lexer/parser/AMT/decision pipeline.
- Added the public browser playground for live source editing and inspection.
- Added automated browser/core parity tests across examples and conformance fixtures.

### Protocols and verification

- Added Render Decision JSON Schema and public Render Decision Protocol documentation.
- Added canonical allow and suppress conformance fixtures.
- Added a machine-readable conformance manifest and independent replication protocol.
- Added reproducible-build tests.
- Added build-manifest hash verification tests that recompute every digest.
- Added explicit tamper-detection tests by mutating an emitted artifact after compilation.
- CI now verifies tests, compilation, bundle integrity, validation, lint, explanation output, inspect output, and benchmark execution.

### Benchmarks

- Added a machine-readable compiler benchmark harness across the public example suite.
- Added environment-controlled benchmark iterations and a reproducible benchmarking protocol.

### Editor and language intelligence

- Added VS Code `.aml` language registration, syntax highlighting, comments, brackets, policy fields, operators, and TextMate scopes.
- Added a shared language-intelligence catalog for editor completions and hover documentation.
- Added a dependency-free Language Server Protocol core with document synchronization, completion, hover, and compiler-backed diagnostics.
- Added the `aml-lsp` stdio server binary with JSON-RPC `Content-Length` framing.
- Added unit tests for LSP behavior and an end-to-end stdio transport initialization test.

### Capability discovery

- Added `AML_CAPABILITIES.json`, a machine-readable manifest of compiler, tooling, policy, editor, integrity, and verification capabilities.
- Added automated tests requiring referenced capability artifacts to exist.

### Examples and research

- Added runnable AML examples for AI assistants, accessibility-first interfaces, calm checkout, and learning mode.
- Added a public example gallery and expanded documentation hub.
- Published research notes on Meaning-Native Computing™, accountable interfaces, AI-generated UI, machine-readable intent, attention as an interface resource, and EthicalRenderGate™.
- Published documentation for policy expressions, semantic diagnostics, benchmarking, build integrity, build verification, language intelligence, and the language server.

### Public surface

- Rebuilt the README as a v1.1 developer, playground, proof, and verification launchpad.
- Strengthened package metadata around accountable rendering, policy-aware UI, semantic UI, AI-generated interfaces, meaning-native computing, and language-server tooling.

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
