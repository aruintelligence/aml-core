# ĀML™ Benchmarking Protocol

## Measure it so someone else can reproduce it

ĀML performance claims should be tied to exact code, exact fixtures, exact environments, and machine-readable results. A fast number without enough context to reproduce it is not useful evidence.

The reference repository already exposes a benchmark harness:

```bash
npm run benchmark
```

The harness exercises `compileSource` across the published example suite and emits JSON. This document defines how benchmark results should be produced, compared, and cited.

## Benchmark principles

1. **Correctness before speed.** A faster implementation that changes required semantic behavior, render decisions, canonicalization, signatures, or verification outcomes is not a valid performance win.
2. **Pin the target.** Report the exact ĀML release or commit SHA.
3. **Pin the corpus.** Report fixture names and, for durable external reports, hashes of the exact fixture bytes.
4. **Pin the environment.** Runtime, operating system, architecture, CPU, memory, and relevant execution flags belong in the report.
5. **Separate benchmark classes.** Compiler throughput, policy evaluation, receipt/signature operations, verifier operations, browser bridges, HTTP service behavior, and end-to-end evaluation should not be collapsed into one number.
6. **Report distributions, not just a best run.** Median and p95 are preferred for repeated timing samples when a benchmark runner supports them. Minimum values may be reported but must not be presented as typical performance.
7. **Preserve negative results.** Regressions, failures, timeouts, and unsupported operations belong in the record.
8. **Do not infer what was not measured.** Software timing does not establish human wellbeing, safety, accessibility outcomes, regulatory compliance, market adoption, certification, or standards status.

## Reference compiler benchmark

The repository's current `benchmarks/run.js` performs ten unreported warm-up compilations per fixture and then measures a configurable number of iterations. The default is 250 iterations per fixture.

To run the default suite:

```bash
npm ci
npm run benchmark
```

To change the measured iteration count:

```bash
AML_BENCH_ITERATIONS=1000 npm run benchmark
```

The reference output includes:

- benchmark name;
- Node version;
- operating-system platform;
- architecture;
- fixture path;
- source byte count;
- measured iterations;
- total elapsed milliseconds;
- average milliseconds per compile;
- compiles per second;
- token count;
- render-decision count.

These fields describe the run; they do not by themselves make two runs comparable.

## Required report envelope

A durable benchmark report SHOULD record:

```json
{
  "schema": "aru-aml-benchmark-report/1",
  "target": {
    "repository": "aruintelligence/aml-core",
    "release": "v1.3.0",
    "commit": "<exact commit sha>"
  },
  "implementation": {
    "name": "<implementation name>",
    "ownership": "reference | independent",
    "language": "<language>",
    "runtime": "<runtime + version>"
  },
  "environment": {
    "os": "<os/version>",
    "arch": "<architecture>",
    "cpu": "<cpu>",
    "memory_bytes": null
  },
  "method": {
    "benchmark_class": "compiler-throughput",
    "warmup_iterations": 10,
    "measured_iterations": 250,
    "runs": 1
  },
  "fixtures": [],
  "results": [],
  "correctness": {
    "conformance_checked": false,
    "negative_tests_checked": false
  },
  "evidence": {
    "requested_level": "E2",
    "report_url": null
  }
}
```

Use `benchmark-report.schema.json` for the machine-readable report contract.

## Benchmark classes

### B1 — Compiler throughput

Measure parsing/compilation against named source fixtures. Record source size and required output characteristics so an implementation cannot improve timing merely by omitting work.

### B2 — Semantic and policy analysis

Measure semantic diffs, policy diffs, profile evaluation, consensus, and related policy machinery independently where practical.

### B3 — Decision and receipt generation

Measure deterministic decision production and receipt construction. If cryptographic signing is included, identify the algorithm and whether key generation is excluded from the measured operation.

### B4 — Verification and tamper rejection

Measure successful verification and deliberately invalid artifacts separately. A verifier must not gain apparent speed by skipping integrity checks.

### B5 — Protocol/interoperability

Measure canonicalization, wire-envelope processing, capability negotiation, or other protocol operations against pinned vectors. Performance is meaningful only after the implementation agrees with the required vectors.

### B6 — Browser integration

Measure browser-facing AML evaluation separately from raw compiler/runtime timing. Record browser/version, device, extension state where relevant, and whether rendering/layout work is included.

### B7 — HTTP/service evaluation

Measure server-side request latency and throughput with clear concurrency, connection, serialization, authentication, and network assumptions. A local loopback benchmark is not equivalent to an Internet deployment benchmark.

### B8 — End-to-end interface decision

Measure the complete path from declared intent/input through policy and decision to evidence output. State exactly which stages are included.

## Comparability rules

Two results should be called directly comparable only when the relevant variables are controlled or explicitly normalized. At minimum compare:

- same contract/release or a documented compatibility target;
- same fixture bytes;
- same operation boundary;
- same correctness expectations;
- same warm-up policy;
- same iteration/sampling method;
- sufficiently described hardware/runtime environment.

Cross-language results are useful, but language/runtime differences must remain visible. Do not relabel a cross-language experiment as an implementation ranking unless the methodology was designed for that purpose.

## Statistical reporting

For serious comparative work, run multiple independent samples rather than relying on one process lifetime. Report at least:

- sample count;
- median;
- p95 when the sample count supports it;
- minimum and maximum when useful;
- failures/timeouts;
- raw samples or an attached machine-readable result where practical.

Avoid false precision. Environmental noise, JIT compilation, garbage collection, CPU frequency scaling, background load, virtualization, and thermal behavior can dominate small timing differences.

## Correctness gate

Before a performance comparison is treated as evidence, the implementation SHOULD pass the relevant correctness surface:

- conformance fixtures;
- canonicalization/golden vectors where applicable;
- expected ALLOW/SUPPRESS behavior;
- receipt/hash/signature verification where included;
- deliberate mutation or tamper-rejection tests where included.

A result that is fast but semantically wrong should be reported as a correctness failure, not a benchmark victory.

## Independent benchmarking

Independent reports are encouraged. Use `docs/INDEPENDENT_BENCHMARK_REPORT_TEMPLATE.md` and publish enough material for another party to reproduce the result.

Independence must be stated rather than implied. Running the ĀRU-owned reference harness on a third-party machine can be independent reproduction of a run, but it is not an independent implementation of AML.

See [EVIDENCE.md](EVIDENCE.md) for evidence levels. In general:

- project-controlled benchmark evidence normally remains project evidence;
- an independently reproduced reference benchmark may support E3 for the tested result;
- an independently implemented compatible runtime may support E4 for the tested contract if its independence and correctness are established;
- pilot or production performance belongs to the corresponding external-deployment evidence level only when the deployment evidence exists.

## What benchmark numbers never prove by themselves

A benchmark result does **not** establish:

- that ĀML is a ratified standard;
- that an organization has adopted ĀML;
- official ĀRU authorization or trademark rights;
- security certification;
- regulatory compliance;
- scientific validation of declared attention/restoration values;
- improved human wellbeing;
- general superiority over HTML, React, policy engines, browsers, or other technologies.

Those are different questions requiring different evidence.

## Reproduce, challenge, publish

A strong result should make disagreement cheap:

1. publish the exact target commit;
2. publish the environment;
3. publish the fixture identity;
4. publish the command or harness;
5. publish machine-readable output;
6. publish correctness status;
7. publish failures as well as successes;
8. invite another implementation or machine to repeat it.

**The goal is not to win a benchmark screenshot. The goal is to make AML performance claims reproducible enough to survive independent scrutiny.**
