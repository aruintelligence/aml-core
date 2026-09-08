# ĀML Benchmark Fixtures

ĀML benchmark claims should be reproducible and tied to named fixtures rather than promotional language.

## Fixture classes

### Compiler throughput
Measure parse/compile time across the published example suite with fixed source files and runtime version.

### Semantic-diff detection
Use paired fixtures where text changes alter declared purpose, privacy, consent, accessibility, attention, or restoration semantics.

### Policy-diff detection
Hold source constant and compare outcomes across named built-in profiles.

### Integrity verification
Measure verification over untouched and deliberately mutated build manifests, receipts, policy packs, attention ledgers, and audit streams.

### Conformance
Compile every entry in `conformance/manifest.json` and report pass/fail against the documented artifact contract.

## Reporting rules

A benchmark report should include:

- AML commit or release;
- Node/runtime version;
- operating system/architecture where relevant;
- fixture names;
- iteration count;
- whether warm-up runs were excluded;
- raw or machine-readable results when practical.

## What not to claim

These software benchmarks do not establish improved human wellbeing, reduced cognitive burden, ethical superiority, or accessibility outcomes. Those questions require separate empirical study.