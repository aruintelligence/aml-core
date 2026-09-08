# ĀML™ Changelog

All notable changes to ĀML™ — ĀRU Meaning Language™ — are documented here.

## [Unreleased]

### Next

- Browser-consumable compiler packaging
- richer semantic policy models
- expanded conformance fixtures
- independent accessibility and adversarial evaluation

## [1.1.0] — 2026-09-07

### Compiler

- Added `compileSource(source)` for pure in-memory AML compilation without filesystem output.
- Preserved `compileAML(inputPath, outputDir)` as the artifact-emitting filesystem compiler.
- Added a stable package entry point exporting `compileAML`, `compileSource`, and `ethicalRenderGate`.

### CLI

- Added `aml validate <file.aml>` for parse/evaluation checks without writing artifacts.
- Added `aml inspect <file.aml>` to emit the Abstract Meaning Tree and render decisions as JSON.
- Removed package scripts that referenced CLI commands not actually implemented.

### Verification

- CI now verifies tests, filesystem compilation, in-memory validation, and inspectable decision output.
- Added compilation coverage for flagship AML examples.
- Added a machine-readable conformance manifest and independent replication protocol.

### Examples and research

- Added runnable AML examples for AI assistants, accessibility-first interfaces, calm checkout, and learning mode.
- Added a public example gallery and expanded documentation hub.
- Published research notes on Meaning-Native Computing™, accountable interfaces, AI-generated UI, machine-readable intent, attention as an interface resource, and EthicalRenderGate™.

### Public surface

- Rebuilt the README as a developer and verification launchpad.
- Strengthened package metadata around accountable rendering, policy-aware UI, semantic UI, AI-generated interfaces, and meaning-native computing.

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
