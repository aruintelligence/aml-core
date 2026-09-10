# ĀML Benchmark Fixtures

ĀML benchmark claims should be reproducible and tied to named fixtures rather than promotional language.

The executable reference harness is:

```bash
npm run benchmark
```

The benchmark method, comparability rules, evidence boundaries, and independent-report requirements are defined in [`BENCHMARKING.md`](../BENCHMARKING.md). Machine-readable reports can use [`benchmark-report.schema.json`](../benchmark-report.schema.json).

## Fixture classes

### Compiler throughput
Measure parse/compile time across the published example suite with fixed source files and runtime version.

The current reference compiler suite contains:

- `examples/simple.aml`
- `examples/transmission-061.aml`
- `examples/ethical_ads.aml`
- `examples/focus_mode.aml`
- `examples/social_feed.aml`
- `examples/learning_mode.aml`
- `examples/accessibility_first.aml`
- `examples/ai_assistant_response.aml`
- `examples/calm_checkout.aml`

The current reference harness performs 10 warm-up compilations per fixture and, by default, 250 measured iterations. `AML_BENCH_ITERATIONS` can change the measured iteration count.

### Semantic-diff detection
Use paired fixtures where text changes alter declared purpose, privacy, consent, accessibility, attention, or restoration semantics.

### Policy-diff detection
Hold source constant and compare outcomes across named built-in profiles.

### Integrity verification
Measure verification over untouched and deliberately mutated build manifests, receipts, policy packs, attention ledgers, and audit streams. Successful verification and rejection paths should be reported separately when their cost differs materially.

### Conformance
Compile every entry in `conformance/manifest.json` and report pass/fail against the documented artifact contract.

### Protocol and independent-runtime verification
When benchmarking canonicalization, signatures, witness bundles, release proofs, or wire/protocol operations, pin the exact protocol/vector version and verify correctness before treating timing as meaningful.

## Fixture identity

For durable or comparative reports, fixture identity SHOULD include:

- repository release or exact commit SHA;
- repository-relative path;
- byte size;
- SHA-256 of the exact fixture bytes;
- expected operation/decision behavior where relevant.

A modified fixture is a new benchmark input. Publish its bytes and hash rather than presenting it as identical to the canonical fixture.

## Reporting rules

A benchmark report should include:

- AML commit or release;
- implementation identity and whether it is reference or independent;
- language/runtime version;
- operating system and architecture;
- CPU and memory for serious comparative reports;
- fixture names and hashes for durable reports;
- benchmark class / exact operation boundary;
- iteration and sample/run counts;
- whether warm-up runs were excluded;
- relevant concurrency and network assumptions;
- correctness/conformance status;
- negative or tamper-test status when verification is measured;
- failures, timeouts, and unsupported cases;
- raw or machine-readable results when practical.

For repeated comparative timing, prefer distributions such as median and p95 over a single best run. Avoid false precision when environmental noise is material.

## Correctness before timing

A timing result is only useful for the work actually performed. Do not claim a performance improvement if required parsing, policy evaluation, canonicalization, receipt construction, cryptographic verification, tamper rejection, or another contract step was skipped.

When implementations are compared, first establish that they satisfy the same relevant correctness contract.

## Independent reports

External testers and implementers can use [`docs/INDEPENDENT_BENCHMARK_REPORT_TEMPLATE.md`](../docs/INDEPENDENT_BENCHMARK_REPORT_TEMPLATE.md).

Independent reproduction of the reference implementation is different from an independent implementation. State which one applies and classify the evidence under [`EVIDENCE.md`](../EVIDENCE.md).

PASS, FAIL, MIXED, regressions, and unsupported results should remain publishable.

## What not to claim

These software benchmarks do not establish improved human wellbeing, reduced cognitive burden, ethical superiority, accessibility outcomes, security certification, regulatory compliance, standards-body status, official ĀRU authorization, market adoption, or general superiority over unrelated technologies. Those questions require separate evidence.
