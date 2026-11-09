#!/usr/bin/env node
// Aggregate public status only. Never print raw report/error/message/flow content.
// Reason codes are emitted ONLY from fixed allowlists of authored enum strings.
import fs from "node:fs";
import { QUALITY_REASON_CODES, VALIDATOR_ERROR_CODES } from "./check-codeql-sarif.mjs";
const language = ["javascript-typescript", "python"].includes(process.argv[3]) ? process.argv[3] : "invalid";
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
let summary = { protocol: "aml-codeql-public-status/1", language, analysis_quality_valid: false, findings_count: null, findings_by_level: null, quality_reason_codes: [] };
const reasons = new Set();
try {
 const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
 if (language === "invalid" || report.protocol !== "aml-codeql-sarif-review/1" || report.language !== language) throw new Error("invalid_status_input");
 const levels = Object.fromEntries(["error", "warning", "note", "none"].map(k => [k, count(report.findings_by_level?.[k])]));
 const total = count(report.findings_count);
 const consistent = total !== null && Object.values(levels).every(v => v !== null) && Object.values(levels).reduce((a,b)=>a+b,0) === total;
 if (!consistent) reasons.add("inconsistent_public_counts");
 if (Object.hasOwn(report, "quality_reason_codes") && !Array.isArray(report.quality_reason_codes)) reasons.add("unclassified_quality_reason");
 else for (const code of report.quality_reason_codes ?? []) reasons.add(QUALITY_REASON_CODES.includes(code) ? code : "unclassified_quality_reason");
 if (report.analysis_quality_valid !== true && reasons.size === 0) reasons.add("unclassified_quality_failure");
 summary = { ...summary, analysis_quality_valid: report.analysis_quality_valid === true && consistent && reasons.size === 0, findings_count: total, findings_by_level: levels };
} catch {
 // Fail closed without exposing the parser error or input bytes. The optional
 // checker stderr file contributes only an allowlisted enum code, never its text.
 reasons.add("invalid_status_input");
 try {
  const error = JSON.parse(fs.readFileSync(process.argv[4], "utf8"))?.error;
  if (typeof error === "string") reasons.add(VALIDATOR_ERROR_CODES.includes(error) ? "validator_" + error : "unclassified_validator_error");
 } catch { /* No checker error file or unreadable: no further detail. */ }
}
summary.quality_reason_codes = [...reasons].sort();
console.log(JSON.stringify(summary));
if (!summary.analysis_quality_valid) process.exitCode = 1;
