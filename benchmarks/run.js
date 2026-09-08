import fs from "node:fs";
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
const timestamp = "2026-01-01T00:00:00.000Z";

const results = [];

for (const file of files) {
  const source = fs.readFileSync(file, "utf8");

  for (let i = 0; i < 10; i++) compileSource(source, { timestamp });

  const start = performance.now();
  let last;
  for (let i = 0; i < iterations; i++) {
    last = compileSource(source, { timestamp });
  }
  const elapsedMs = performance.now() - start;

  results.push({
    file,
    source_bytes: Buffer.byteLength(source),
    iterations,
    total_ms: Number(elapsedMs.toFixed(3)),
    average_ms: Number((elapsedMs / iterations).toFixed(4)),
    compiles_per_second: Number((iterations / (elapsedMs / 1000)).toFixed(1)),
    tokens: last.tokens.length,
    decisions: last.renderDecisions.length
  });
}

console.log(JSON.stringify({
  benchmark: "aml-core compileSource",
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  results
}, null, 2));
