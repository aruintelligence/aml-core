# Action-boundary local performance snapshot

Run on 2026-11-04 from source commit `f0d3e2dbdaaf6b1bb779c7c150f24144a23184e5`, Linux/x64, Node `v24.22.1`. Command: `node benchmarks/action-boundary.mjs > audit/AML_ACTION_BENCHMARK_20261104.json`. The exact machine-readable sample, including RSS before/after each case, is in that JSON file. The worktree contained only the new result/report when the measurement was taken.

Fixture: one 452-byte canonical proposed action; 50 warmups per case, then 500 sequential iterations except 20 file-grant pairs; 100 calls in one concurrent Promise batch. The callback returns `true` without provider I/O in both guarded and unprotected paths. All required checks remained enabled. The script completed without an exception (zero observed benchmark failures).

| Operation | N | Median ms | p95 ms | Sequential throughput / s |
| --- | ---: | ---: | ---: | ---: |
| Canonicalization | 500 | 0.0147 | 0.1194 | 16,533.5 |
| SHA-256 of canonical bytes | 500 | 0.0022 | 0.0154 | 44,210.0 |
| Policy plan and digest | 500 | 0.0153 | 0.2891 | 12,853.5 |
| Same unprotected callback | 500 | 0.0002 | 0.0006 | 289,863.0 |
| Guarded callback, rule needs no approval | 500 | 0.0287 | 1.2095 | 5,168.3 |
| Guarded callback, process-local one-use approval | 500 | 0.0569 | 1.7020 | 2,837.7 |
| Local file grant issue and consume | 20 | 72.5549 | 128.2370 | 13.2 |

The 100-call Promise batch took **19.5008 ms** on this run (5,128 calls/s). It is event-loop concurrency, not multi-host or multi-core throughput. RSS rose from about 40.2 MB before the first case to 49.3 MB after the file case; these are process-wide snapshots affected by JIT, allocation and garbage collection, not a per-request memory cost. The unusually large p95 values and file sync latency on this shared environment should be repeated on target hardware before setting service-level objectives. The unprotected callback performs no canonicalization, policy or receipt work; its extremely small timing is a comparison baseline, not a real provider workload.

This benchmark does **not** measure a real authenticated approval UI, cryptographic receipt verification, distributed grant store, provider request/acceptance/completion, sustained load, or error-path latency. In `aml-action-dispatch/1`, the local receipt is not a signed provider completion receipt. No claim of a production throughput or independent benchmark follows from this run.
