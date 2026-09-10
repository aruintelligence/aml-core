import fs from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: node scripts/check-benchmark-report.mjs <report.json>");
  process.exit(2);
}

let report;
try {
  report = JSON.parse(fs.readFileSync(file, "utf8"));
} catch (error) {
  console.error(`invalid benchmark JSON: ${error.message}`);
  process.exit(1);
}

const errors = [];
const requireValue = (condition, message) => {
  if (!condition) errors.push(message);
};

requireValue(report.schema === "aru-aml-benchmark-report/1", "wrong benchmark report schema");
requireValue(report.target?.repository === "aruintelligence/aml-core", "wrong benchmark target repository");
requireValue(typeof report.target?.release === "string" && report.target.release.length > 0, "missing benchmark target release");
requireValue(report.target?.commit === null || typeof report.target?.commit === "string", "benchmark target commit must be string or null");
requireValue(report.implementation?.ownership === "reference", "reference harness must identify ownership=reference");
requireValue(report.implementation?.language === "JavaScript", "reference harness must identify JavaScript implementation");
requireValue(typeof report.implementation?.runtime === "string" && report.implementation.runtime.includes("Node.js"), "missing Node.js runtime identity");
requireValue(typeof report.environment?.os === "string" && report.environment.os.length > 0, "missing operating-system identity");
requireValue(typeof report.environment?.arch === "string" && report.environment.arch.length > 0, "missing architecture identity");
requireValue(report.method?.benchmark_class === "compiler-throughput", "reference harness must identify compiler-throughput class");
requireValue(Number.isInteger(report.method?.warmup_iterations) && report.method.warmup_iterations >= 0, "invalid warmup iteration count");
requireValue(Number.isInteger(report.method?.measured_iterations) && report.method.measured_iterations >= 1, "invalid measured iteration count");
requireValue(report.method?.runs === 1, "reference harness currently reports one measured run");
requireValue(Array.isArray(report.fixtures) && report.fixtures.length === 9, "reference harness must report exactly nine canonical fixtures");
requireValue(Array.isArray(report.results) && report.results.length === report.fixtures?.length, "benchmark result count must match fixture count");

const fixtureNames = new Set();
for (const fixture of report.fixtures || []) {
  requireValue(typeof fixture.name === "string" && fixture.name.length > 0, "fixture missing name");
  requireValue(!fixtureNames.has(fixture.name), `duplicate fixture: ${fixture.name}`);
  fixtureNames.add(fixture.name);
  requireValue(typeof fixture.sha256 === "string" && /^[a-f0-9]{64}$/.test(fixture.sha256), `${fixture.name}: invalid SHA-256`);
  requireValue(Number.isInteger(fixture.bytes) && fixture.bytes > 0, `${fixture.name}: invalid byte count`);
}

for (const result of report.results || []) {
  requireValue(fixtureNames.has(result.fixture), `result references unknown fixture: ${result.fixture}`);
  requireValue(result.status === "PASS", `${result.fixture}: reference compile benchmark must report PASS or fail execution`);
  requireValue(typeof result.average_ms === "number" && result.average_ms >= 0, `${result.fixture}: invalid average_ms`);
  requireValue(typeof result.operations_per_second === "number" && result.operations_per_second >= 0, `${result.fixture}: invalid operations_per_second`);
  requireValue(result.iterations === report.method?.measured_iterations, `${result.fixture}: result iterations disagree with method`);
  requireValue(Number.isInteger(result.tokens) && result.tokens >= 0, `${result.fixture}: invalid token count`);
  requireValue(Number.isInteger(result.decisions) && result.decisions >= 0, `${result.fixture}: invalid decision count`);
}

requireValue(report.correctness?.conformance_checked === false, "standalone benchmark must not falsely claim conformance was checked inside the benchmark process");
requireValue(report.correctness?.negative_tests_checked === false, "standalone benchmark must not falsely claim negative tests were checked inside the benchmark process");
requireValue(report.evidence?.requested_level === "E2", "project-controlled reference benchmark should request E2, not external evidence level");
requireValue(typeof report.evidence?.independence_statement === "string" && /not independent/i.test(report.evidence.independence_statement), "benchmark report must state that project output is not independent evidence");

const output = {
  schema: "aru-aml-benchmark-report-check/1",
  valid: errors.length === 0,
  fixtures: report.fixtures?.length || 0,
  results: report.results?.length || 0,
  errors
};

console.log(JSON.stringify(output, null, 2));
if (errors.length) process.exit(1);
