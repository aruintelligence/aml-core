import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { executeAccountableIntent, verifyExecutionReceipt, viewMeaning } from "../../index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const timestamp = "2026-09-08T00:00:00.000Z";
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fixture = (name) => fs.readFileSync(path.join(here, name));
const load = (name) => JSON.parse(fixture(name).toString("utf8"));

const scenarios = [
  {
    id: "calm_explanation",
    intent_file: "intent-allowed.json",
    context_file: "context-denied.json",
    expected: { allowed: 1, suppressed: 0 }
  },
  {
    id: "sensitive_without_consent",
    intent_file: "intent-sensitive.json",
    context_file: "context-denied.json",
    expected: { allowed: 0, suppressed: 1 }
  },
  {
    id: "sensitive_with_consent",
    intent_file: "intent-sensitive.json",
    context_file: "context-allowed.json",
    expected: { allowed: 1, suppressed: 0 }
  }
];

const results = scenarios.map((scenario) => {
  const receipt = executeAccountableIntent(load(scenario.intent_file), {
    profile: "human_first",
    context: load(scenario.context_file),
    timestamp,
    stream_id: `enterprise-pilot-${scenario.id}`
  });
  const integrity = verifyExecutionReceipt(receipt);
  const counts_match = receipt.selected_render.allowed === scenario.expected.allowed &&
    receipt.selected_render.suppressed === scenario.expected.suppressed;

  return {
    id: scenario.id,
    intent_file: scenario.intent_file,
    intent_file_sha256: sha256(fixture(scenario.intent_file)),
    context_file: scenario.context_file,
    context_file_sha256: sha256(fixture(scenario.context_file)),
    expected: scenario.expected,
    counts_match,
    receipt_verified: integrity.verified,
    receipt,
    meaning: viewMeaning(receipt)
  };
});

// A negative control shows that the verifier catches a mutation to the data
// bound by the receipt hash. This is not a signature or independent audit.
const tampered = structuredClone(results[0].receipt);
tampered.intent.transmission = "tampered-after-evaluation";
const tamper_rejected = verifyExecutionReceipt(tampered).verified === false;

const report = {
  protocol: "aml-enterprise-pilot-report/1",
  profile: "human_first",
  decision_timestamp: timestamp,
  source_revision: process.env.GITHUB_SHA || null,
  evidence_level: "project-authored demonstration",
  claim_boundary: "Declared prototype policy inputs; no objective human-impact measurement, independent validation, certification, or production approval.",
  passed: results.every((result) => result.counts_match && result.receipt_verified) && tamper_rejected,
  tamper_rejected,
  scenarios: results
};
report.report_sha256 = sha256(JSON.stringify(report));
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.passed) process.exitCode = 1;
