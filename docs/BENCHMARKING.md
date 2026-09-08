# ĀML™ Benchmarking Protocol

ĀML performance claims should be reproducible, machine-readable, and separated from claims about human attention or wellbeing.

## Run the benchmark

```bash
npm install
npm test
npm run benchmark
```

The harness compiles the public example suite repeatedly through the pure in-memory `compileSource()` pipeline and prints JSON containing:

- source file
- source bytes
- iteration count
- total elapsed milliseconds
- average compile milliseconds
- compiles per second
- token count
- render-decision count
- Node.js version
- platform and architecture

## Control the workload

The default is 250 measured compilations per example after a short warm-up.

```bash
AML_BENCH_ITERATIONS=1000 npm run benchmark
```

## Reproducibility

The benchmark supplies a fixed accountability timestamp so decision artifacts remain deterministic during measurement.

This matters because timestamps are useful provenance in normal compilation but should not introduce irrelevant output differences in reproducibility tests.

## Reporting results

When publishing benchmark numbers, include:

1. commit SHA;
2. Node.js version;
3. operating system and architecture;
4. iteration count;
5. complete JSON output;
6. whether the machine was under unusual load.

Do not compare benchmark numbers from materially different environments as though they were controlled measurements.

## Scope

This benchmark measures prototype compiler throughput only. It does **not** measure user attention, restoration, accessibility quality, ethical quality, or real-world application performance.
