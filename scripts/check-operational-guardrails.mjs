import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fail(message) { console.error(message); process.exit(1); }

const protocols = readJson('protocol-compatibility.json');
const perf = readJson('performance-budget.json');
const resources = readJson('resource-limits.json');

if (protocols.protocol !== 'aml-protocol-compatibility/1') fail('Unexpected protocol compatibility contract version');
if (!Array.isArray(protocols.stable_protocols) || protocols.stable_protocols.length === 0) fail('No stable protocols declared');
const seen = new Set();
for (const id of protocols.stable_protocols) {
  if (!/^[a-z0-9-]+\/[1-9][0-9]*$/.test(id)) fail(`Invalid protocol identifier: ${id}`);
  if (seen.has(id)) fail(`Duplicate protocol identifier: ${id}`);
  seen.add(id);
}

if (!(perf.ci_iterations > 0 && perf.max_average_ms_per_fixture > 0 && perf.max_total_ms_all_fixtures > 0)) fail('Invalid performance budget');
const bench = spawnSync(process.execPath, ['benchmarks/run.js'], {
  encoding: 'utf8',
  env: { ...process.env, AML_BENCH_ITERATIONS: String(perf.ci_iterations) },
  maxBuffer: 8 * 1024 * 1024,
  timeout: Math.ceil(perf.max_total_ms_all_fixtures + 15000)
});
if (bench.error?.code === 'ETIMEDOUT') fail('Benchmark exceeded operational timeout');
if (bench.status !== 0) fail(`Benchmark failed: ${bench.stderr || bench.stdout}`);
const report = JSON.parse(bench.stdout);
const total = report.results.reduce((sum, item) => sum + item.total_ms, 0);
const slow = report.results.filter(item => item.average_ms > perf.max_average_ms_per_fixture);
if (slow.length) fail(`Performance budget exceeded: ${slow.map(item => `${item.fixture}=${item.average_ms}ms`).join(', ')}`);
if (total > perf.max_total_ms_all_fixtures) fail(`Total benchmark budget exceeded: ${total}ms`);

const fuzzSource = fs.readFileSync('scripts/check-deterministic-fuzz.mjs', 'utf8');
const limits = resources.deterministic_fuzz;
for (const [needle, label] of [
  [`${limits.max_case_bytes}`, 'max_case_bytes'],
  [`timeout: ${limits.per_case_timeout_ms}`, 'per_case_timeout_ms'],
  [`maxBuffer: ${limits.max_worker_output_bytes}`, 'max_worker_output_bytes']
]) {
  if (!fuzzSource.includes(needle)) fail(`Fuzz implementation drifted from ${label} resource contract`);
}

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-operational-guardrails-report/1',
  stable_protocol_count: protocols.stable_protocols.length,
  performance: {
    fixture_count: report.results.length,
    max_average_ms_observed: Math.max(...report.results.map(item => item.average_ms)),
    total_ms_observed: Number(total.toFixed(3)),
    max_average_ms_budget: perf.max_average_ms_per_fixture,
    max_total_ms_budget: perf.max_total_ms_all_fixtures
  },
  resource_limits: limits,
  claim_boundary: 'Project-controlled operational regression checks only; not certification, an SLA, or proof of immunity to denial-of-service attacks.'
}, null, 2));
