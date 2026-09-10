import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { compileSource } from "../index.js";

const files = [
  "examples/simple.aml",
  "examples/transmission-061.aml",
  "examples/ethical_ads.aml",
  "examples/focus_mode.aml",
  "examples/social_feed.aml",
  "examples/learning_mode.aml",
  "examples/accessibility_first.aml",
  "examples/ai_assistant_response.aml",
  "examples/calm_checkout.aml"
];

const iterations = Number(process.env.AML_BENCH_ITERATIONS || 250);
const warmupIterations = 10;
const timestamp = "2026-01-01T00:00:00.000Z";
const packageJson = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function currentCommit() {
  if (process.env.AML_BENCH_COMMIT) return process.env.AML_BENCH_COMMIT;
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

const fixtures = [];
const results = [];

for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  const sourceBytes = Buffer.byteLength(source);

  fixtures.push({
    name: file,
    sha256: sha256(Buffer.from(source, "utf8")),
    bytes: sourceBytes
  });

  for (let i = 0; i < warmupIterations; i++) compileSource(source, { timestamp });

  const start = performance.now();
  let last;
  for (let i = 0; i < iterations; i++) {
    last = compileSource(source, { timestamp });
  }
  const elapsedMs = performance.now() - start;
  const averageMs = elapsedMs / iterations;
  const operationsPerSecond = iterations / (elapsedMs / 1000);

  results.push({
    fixture: file,
    status: "PASS",
    average_ms: Number(averageMs.toFixed(4)),
    operations_per_second: Number(operationsPerSecond.toFixed(1)),
    source_bytes: sourceBytes,
    iterations,
    total_ms: Number(elapsedMs.toFixed(3)),
    compiles_per_second: Number(operationsPerSecond.toFixed(1)),
    tokens: last.tokens.length,
    decisions: last.renderDecisions.length
  });
}

const cpu = os.cpus()?.[0]?.model || null;
const commit = currentCommit();

console.log(JSON.stringify({
  schema: "aru-aml-benchmark-report/1",
  target: {
    repository: "aruintelligence/aml-core",
    release: `v${packageJson.version}`,
    commit
  },
  implementation: {
    name: "aml-core JavaScript reference runtime",
    ownership: "reference",
    language: "JavaScript",
    runtime: `Node.js ${process.version}`,
    source_url: "https://github.com/aruintelligence/aml-core"
  },
  environment: {
    os: `${os.type()} ${os.release()}`,
    arch: process.arch,
    cpu,
    memory_bytes: os.totalmem(),
    browser: null,
    virtualized: null
  },
  method: {
    benchmark_class: "compiler-throughput",
    warmup_iterations: warmupIterations,
    measured_iterations: iterations,
    runs: 1,
    concurrency: 1,
    deterministic_timestamp: timestamp,
    notes: "Each fixture is warmed independently. Timed work measures compileSource calls only. File reads, fixture hashing, environment discovery, and report serialization are excluded from the measured interval."
  },
  fixtures,
  results,
  correctness: {
    conformance_checked: false,
    conformance_status: "NOT_CHECKED",
    negative_tests_checked: false,
    negative_test_status: "NOT_CHECKED",
    details_url: "https://github.com/aruintelligence/aml-core/actions"
  },
  evidence: {
    requested_level: "E2",
    report_url: null,
    independence_statement: "Project-controlled reference benchmark output; not independent reproduction or third-party adoption."
  },

  // Backwards-compatible summary fields retained for existing consumers.
  benchmark: "aml-core compileSource",
  node: process.version,
  platform: process.platform,
  arch: process.arch
}, null, 2));
