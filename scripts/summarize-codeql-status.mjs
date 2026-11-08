#!/usr/bin/env node
// Aggregate public status only. Never print raw report/error/message/flow content.
import fs from "node:fs";
const language = ["javascript-typescript", "python"].includes(process.argv[3]) ? process.argv[3] : "invalid";
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
let summary = { protocol: "aml-codeql-public-status/1", language, analysis_quality_valid: false, findings_count: null, findings_by_level: null };
try {
 const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
 if (language === "invalid" || report.protocol !== "aml-codeql-sarif-review/1" || report.language !== language) throw new Error("invalid_status_input");
 const levels = Object.fromEntries(["error", "warning", "note", "none"].map(k => [k, count(report.findings_by_level?.[k])]));
 const total = count(report.findings_count);
 summary = { ...summary, analysis_quality_valid: report.analysis_quality_valid === true && total !== null && Object.values(levels).every(v => v !== null) && Object.values(levels).reduce((a,b)=>a+b,0) === total, findings_count: total, findings_by_level: levels };
} catch { /* Fail closed without exposing the parser error or input bytes. */ }
console.log(JSON.stringify(summary));
if (!summary.analysis_quality_valid) process.exitCode = 1;
