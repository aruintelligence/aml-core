import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const errors = [];
const checks = [];

function fail(message) {
  errors.push(message);
}

function pass(message) {
  checks.push(message);
}

function readJson(rel) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) {
    fail(`missing required JSON file: ${rel}`);
    return null;
  }
  try {
    const value = JSON.parse(fs.readFileSync(full, "utf8"));
    pass(`valid JSON: ${rel}`);
    return value;
  } catch (error) {
    fail(`invalid JSON in ${rel}: ${error.message}`);
    return null;
  }
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) fail(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  else pass(`${label} = ${JSON.stringify(expected)}`);
}

function requireArray(value, label) {
  if (!Array.isArray(value)) {
    fail(`${label}: expected array`);
    return false;
  }
  return true;
}

function requireLocalPath(rel, label) {
  if (typeof rel !== "string" || rel.length === 0) {
    fail(`${label}: invalid local path`);
    return;
  }
  const normalized = rel.replace(/\/$/, "");
  if (!fs.existsSync(path.join(root, normalized))) fail(`${label}: missing repository path ${rel}`);
  else pass(`${label}: ${rel}`);
}

function isHttp(value) {
  return typeof value === "string" && /^https?:\/\//i.test(value);
}

const discovery = readJson("aml-discovery.json");
if (discovery) {
  requireEqual(discovery.schema, "aru-aml-discovery/1", "discovery schema");
  requireEqual(discovery.project?.repository, "https://github.com/aruintelligence/aml-core", "discovery repository");

  for (const [name, rel] of Object.entries(discovery.entry_points || {})) {
    if (!isHttp(rel)) requireLocalPath(rel, `discovery entry_points.${name}`);
  }
  for (const [name, rel] of Object.entries(discovery.verification || {})) {
    if (!isHttp(rel)) requireLocalPath(rel, `discovery verification.${name}`);
  }
  for (const [name, rel] of Object.entries(discovery.licensing || {})) {
    if (!isHttp(rel)) requireLocalPath(rel, `discovery licensing.${name}`);
  }

  const boundary = discovery.claim_boundaries || {};
  requireEqual(boundary.working_research_prototype, true, "discovery working_research_prototype");
  requireEqual(boundary.ratified_global_standard, false, "discovery ratified_global_standard");
  requireEqual(boundary.universal_adoption_claimed, false, "discovery universal_adoption_claimed");
  requireEqual(boundary.objective_cognition_measurement_claimed, false, "discovery objective_cognition_measurement_claimed");
  requireEqual(boundary.third_party_certification_claimed, false, "discovery third_party_certification_claimed");
  requireEqual(boundary.technical_conformance_implies_official_brand_authorization, false, "discovery technical_conformance_implies_official_brand_authorization");
}

const adoption = readJson("adoption-path.json");
if (adoption) {
  requireEqual(adoption.schema, "aru-aml-adoption-path/1", "adoption schema");
  if (requireArray(adoption.stages, "adoption stages")) {
    const ids = adoption.stages.map((stage) => stage.id);
    const expected = Array.from({ length: adoption.stages.length }, (_, i) => i);
    if (JSON.stringify(ids) !== JSON.stringify(expected)) fail(`adoption stage ids must be contiguous from 0: got ${JSON.stringify(ids)}`);
    else pass("adoption stage ids are contiguous from 0");

    const names = new Set();
    for (const stage of adoption.stages) {
      if (!stage || typeof stage.name !== "string" || !stage.name) fail(`adoption stage ${stage?.id}: missing name`);
      else if (names.has(stage.name)) fail(`duplicate adoption stage name: ${stage.name}`);
      else names.add(stage.name);
      if (!stage || typeof stage.goal !== "string" || !stage.goal) fail(`adoption stage ${stage?.id}: missing goal`);
      for (const [index, entry] of (stage?.entrypoints || []).entries()) {
        if (!isHttp(entry)) requireLocalPath(entry, `adoption stage ${stage.id} entrypoint[${index}]`);
      }
    }
  }
}

const evidence = readJson("evidence-levels.json");
if (evidence) {
  requireEqual(evidence.schema, "aru-aml-evidence-levels/1", "evidence schema");
  if (requireArray(evidence.levels, "evidence levels")) {
    const expected = Array.from({ length: 8 }, (_, i) => `E${i}`);
    const actual = evidence.levels.map((level) => level.id);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`evidence levels must be exactly E0-E7 in order: got ${JSON.stringify(actual)}`);
    else pass("evidence levels are exactly E0-E7");

    for (const level of evidence.levels) {
      if (typeof level.name !== "string" || !level.name) fail(`${level.id}: missing evidence level name`);
      if (typeof level.project_controlled !== "boolean") fail(`${level.id}: project_controlled must be boolean`);
      if (typeof level.description !== "string" || !level.description) fail(`${level.id}: missing evidence level description`);
    }
    for (const level of evidence.levels.slice(0, 3)) requireEqual(level.project_controlled, true, `${level.id} project_controlled`);
    for (const level of evidence.levels.slice(3)) requireEqual(level.project_controlled, false, `${level.id} project_controlled`);
  }
  requireLocalPath(evidence.canonical_human_readable, "evidence canonical_human_readable");
  requireLocalPath(evidence.report_template, "evidence report_template");
}

const matrix = readJson("implementation-matrix.json");
if (matrix) {
  requireEqual(matrix.schema, "aru-aml-implementation-matrix/1", "implementation matrix schema");
  requireEqual(matrix.repository, "https://github.com/aruintelligence/aml-core", "implementation matrix repository");
  requireEqual(matrix.standards_status, "not a ratified industry or Internet standard", "implementation matrix standards status");
  if (requireArray(matrix.entries, "implementation matrix entries")) {
    const ids = new Set();
    for (const entry of matrix.entries) {
      if (!entry || typeof entry.id !== "string" || !entry.id) {
        fail("implementation entry missing id");
        continue;
      }
      if (ids.has(entry.id)) fail(`duplicate implementation id: ${entry.id}`);
      ids.add(entry.id);
      if (!Array.isArray(entry.contracts) || entry.contracts.length === 0) fail(`${entry.id}: contracts must be non-empty`);
      if (typeof entry.external_witness !== "boolean") fail(`${entry.id}: external_witness must be boolean`);
      if (typeof entry.third_party_adoption !== "boolean") fail(`${entry.id}: third_party_adoption must be boolean`);
      if (entry.ownership === "project-controlled") {
        requireEqual(entry.external_witness, false, `${entry.id} project-controlled external_witness`);
        requireEqual(entry.third_party_adoption, false, `${entry.id} project-controlled third_party_adoption`);
      }
    }
  }
  const expectedInterop = ["I0", "I1", "I2", "I3", "I4", "I5", "I6"];
  const actualInterop = Object.keys(matrix.interoperability_levels || {});
  if (JSON.stringify(actualInterop) !== JSON.stringify(expectedInterop)) fail(`interoperability levels must be I0-I6 in order: got ${JSON.stringify(actualInterop)}`);
  else pass("interoperability levels are exactly I0-I6");
}

const benchmarkSchema = readJson("benchmark-report.schema.json");
if (benchmarkSchema) {
  requireEqual(benchmarkSchema.$schema, "https://json-schema.org/draft/2020-12/schema", "benchmark JSON Schema dialect");
  requireEqual(benchmarkSchema.properties?.schema?.const, "aru-aml-benchmark-report/1", "benchmark report schema id");
  if (!Array.isArray(benchmarkSchema.required) || !benchmarkSchema.required.includes("correctness")) fail("benchmark report schema must require correctness");
  else pass("benchmark report schema requires correctness");
}

for (const rel of [
  "BENCHMARKING.md",
  "ADOPTION.md",
  "EVIDENCE.md",
  "INTEROPERABILITY.md",
  "CHALLENGES.md",
  "DISCOVER_AML.md",
  "PUBLICATIONS.md",
  "llms.txt",
  "docs/SECURITY_EVALUATION_CHECKLIST.md",
  "docs/INDEPENDENT_BENCHMARK_REPORT_TEMPLATE.md",
  "docs/IMPLEMENTATION_REPORT_TEMPLATE.md"
]) requireLocalPath(rel, "required public contract surface");

const result = {
  schema: "aru-aml-public-contract-guard/1",
  valid: errors.length === 0,
  checks,
  errors
};

console.log(JSON.stringify(result, null, 2));
if (errors.length) process.exit(1);
