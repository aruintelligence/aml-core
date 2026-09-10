import fs from "node:fs";

const file = "external-evidence.json";
const canonicalRepo = "https://github.com/aruintelligence/aml-core";
const allowedLevels = ["E3", "E4", "E5", "E6", "E7"];
const allowedResults = ["PASS", "FAIL", "MIXED", "UNSUPPORTED"];
const errors = [];
const checks = [];

function fail(message) { errors.push(message); }
function pass(message) { checks.push(message); }
function requireValue(condition, message) { condition ? pass(message) : fail(message); }

let registry;
try {
  registry = JSON.parse(fs.readFileSync(file, "utf8"));
  pass(`valid JSON: ${file}`);
} catch (error) {
  console.error(JSON.stringify({ schema: "aru-aml-external-evidence-registry-check/1", valid: false, errors: [`invalid ${file}: ${error.message}`] }, null, 2));
  process.exit(1);
}

requireValue(registry.schema === "aru-aml-external-evidence-registry/1", "registry schema is canonical");
requireValue(registry.canonical_repository === canonicalRepo, "canonical repository identity is correct");
requireValue(JSON.stringify(registry.allowed_evidence_levels) === JSON.stringify(allowedLevels), "allowed evidence levels are exactly E3-E7");
requireValue(JSON.stringify(registry.allowed_results) === JSON.stringify(allowedResults), "allowed results are exactly PASS/FAIL/MIXED/UNSUPPORTED");
requireValue(Array.isArray(registry.records), "records is an array");
requireValue(Number.isInteger(registry.external_evidence_count) && registry.external_evidence_count >= 0, "external_evidence_count is a nonnegative integer");
requireValue(registry.external_evidence_count === registry.records?.length, "external_evidence_count matches records length");

const acceptance = registry.acceptance || {};
requireValue(acceptance.requires_public_evidence_url === true, "public evidence URL is required");
requireValue(acceptance.requires_source_outside_canonical_repository === true, "external source boundary is required");
requireValue(acceptance.requires_independence_statement === true, "independence statement is required");
requireValue(acceptance.requires_scope_boundary === true, "scope boundary is required");
requireValue(acceptance.negative_results_allowed === true, "negative results remain allowed");
requireValue(acceptance.project_controlled_evidence_allowed === false, "project-controlled evidence is forbidden from external registry");
requireValue(acceptance.automatic_level_grant_from_issue_submission === false, "issue submission does not automatically grant an evidence level");

const ids = new Set();
for (const [index, record] of (registry.records || []).entries()) {
  const label = `record[${index}]`;
  requireValue(record && typeof record === "object" && !Array.isArray(record), `${label} is an object`);
  if (!record || typeof record !== "object" || Array.isArray(record)) continue;

  requireValue(typeof record.id === "string" && record.id.length > 0, `${label} has id`);
  if (typeof record.id === "string") {
    requireValue(!ids.has(record.id), `${label} id is unique`);
    ids.add(record.id);
  }

  requireValue(allowedLevels.includes(record.evidence_level), `${label} evidence_level is E3-E7`);
  requireValue(allowedResults.includes(record.result), `${label} result vocabulary is valid`);
  requireValue(typeof record.evidence_url === "string" && /^https:\/\//i.test(record.evidence_url), `${label} has HTTPS evidence_url`);
  requireValue(typeof record.independence_statement === "string" && record.independence_statement.trim().length > 0, `${label} has independence statement`);
  requireValue(typeof record.scope_boundary === "string" && record.scope_boundary.trim().length > 0, `${label} has scope boundary`);
  requireValue(typeof record.reviewed_at === "string" && /^\d{4}-\d{2}-\d{2}/.test(record.reviewed_at), `${label} has reviewed_at date`);
  requireValue(typeof record.source_issue_or_report === "string" && record.source_issue_or_report.trim().length > 0, `${label} has source issue/report`);

  const url = String(record.evidence_url || "").toLowerCase();
  requireValue(!url.startsWith("https://github.com/aruintelligence/aml-core") && !url.startsWith("https://raw.githubusercontent.com/aruintelligence/aml-core"), `${label} evidence URL is outside canonical repository`);

  if (record.project_controlled !== undefined) requireValue(record.project_controlled === false, `${label} is explicitly not project-controlled`);
  if (record.third_party_adoption !== undefined && record.evidence_level === "E3") {
    requireValue(record.third_party_adoption === false, `${label} E3 reproduction is not automatically third-party adoption`);
  }

  if (record.evidence_level === "E4") requireValue(typeof record.implementation_source_url === "string" && /^https:\/\//i.test(record.implementation_source_url), `${label} E4 has public implementation source`);
  if (["E5", "E6", "E7"].includes(record.evidence_level)) requireValue(typeof record.external_context === "string" && record.external_context.trim().length > 0, `${label} ${record.evidence_level} identifies external context`);
  if (record.evidence_level === "E7") requireValue(Number.isInteger(record.independent_party_count) && record.independent_party_count >= 2, `${label} E7 identifies at least two independent parties`);
}

for (const [name, rel] of Object.entries(registry.submission_paths || {})) {
  requireValue(typeof rel === "string" && fs.existsSync(rel), `submission path ${name} exists: ${rel}`);
}

requireValue(typeof registry.specialized_registries?.verifier_witnesses === "string" && fs.existsSync(registry.specialized_registries.verifier_witnesses), "specialized witness registry exists");
requireValue(fs.existsSync("EXTERNAL_EVIDENCE.md"), "human-readable external evidence policy exists");

console.log(JSON.stringify({
  schema: "aru-aml-external-evidence-registry-check/1",
  valid: errors.length === 0,
  external_evidence_count: registry.records?.length || 0,
  checks,
  errors
}, null, 2));

if (errors.length) process.exit(1);
