import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { executeAccountableIntent, verifyExecutionReceipt, viewMeaning } from "../../index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fixture = (name) => fs.readFileSync(path.join(here, name));
const cases = [
  ["calm_explanation", "intent-allowed.json", "context-denied.json", 1, 0],
  ["sensitive_without_consent", "intent-sensitive.json", "context-denied.json", 0, 1],
  ["sensitive_with_consent", "intent-sensitive.json", "context-allowed.json", 1, 0]
];

function requireTrue(condition, message) {
  if (!condition) throw new Error(message);
}

try {
  requireTrue(process.argv.length === 3, "Usage: node pilots/enterprise-30min/verify-report.mjs REPORT.json");
  const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const { report_sha256, ...payload } = report;
  requireTrue(report_sha256 === sha256(JSON.stringify(payload)), "report digest mismatch");
  requireTrue(report.protocol === "aml-enterprise-pilot-report/1", "unsupported report protocol");
  requireTrue(report.profile === "human_first" && report.passed === true, "pilot did not pass");
  requireTrue(report.decision_timestamp === "2026-09-08T00:00:00.000Z", "decision timestamp drift");
  requireTrue(Array.isArray(report.scenarios) && report.scenarios.length === cases.length, "scenario count drift");

  for (const [index, [id, intentFile, contextFile, allowed, suppressed]] of cases.entries()) {
    const result = report.scenarios[index];
    requireTrue(result.id === id && result.intent_file === intentFile && result.context_file === contextFile, `${id}: fixture identity drift`);
    const intentBytes = fixture(intentFile);
    const contextBytes = fixture(contextFile);
    requireTrue(result.intent_file_sha256 === sha256(intentBytes), `${id}: intent fixture mismatch`);
    requireTrue(result.context_file_sha256 === sha256(contextBytes), `${id}: context fixture mismatch`);
    requireTrue(result.expected?.allowed === allowed && result.expected?.suppressed === suppressed, `${id}: expected counts drift`);

    const receipt = result.receipt;
    requireTrue(verifyExecutionReceipt(receipt).verified, `${id}: invalid receipt`);
    requireTrue(receipt.selected_render.allowed === allowed && receipt.selected_render.suppressed === suppressed, `${id}: decision mismatch`);
    requireTrue(result.receipt_verified === true && result.counts_match === true, `${id}: result flags mismatch`);
    requireTrue(JSON.stringify(result.meaning) === JSON.stringify(viewMeaning(receipt)), `${id}: View Meaning mismatch`);

    const replay = executeAccountableIntent(JSON.parse(intentBytes), {
      profile: "human_first",
      context: JSON.parse(contextBytes),
      timestamp: report.decision_timestamp,
      stream_id: `enterprise-pilot-${id}`
    });
    requireTrue(replay.receipt_sha256 === receipt.receipt_sha256, `${id}: replay mismatch`);
  }

  const tampered = structuredClone(report.scenarios[0].receipt);
  tampered.intent.transmission = "tampered-after-evaluation";
  requireTrue(report.tamper_rejected === true && !verifyExecutionReceipt(tampered).verified, "tamper rejection failed");
  process.stdout.write(`${JSON.stringify({ protocol: "aml-enterprise-pilot-verification/1", verified: true, report_sha256, scenarios: cases.length })}\n`);
} catch (error) {
  console.error(`Enterprise pilot report rejected: ${error.message}`);
  process.exitCode = 1;
}
