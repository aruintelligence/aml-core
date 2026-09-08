#!/usr/bin/env node
import fs from "node:fs";
import { evaluatePullRequestChange, formatPullRequestGate } from "../tooling/prGate.js";

const [beforePath, afterPath, beforePolicy = "calm_default", afterPolicy = "human_first", contextPath] = process.argv.slice(2);
if (!beforePath || !afterPath) {
  console.error("Usage: node scripts/meaning-gate.js <before.aml> <after.aml> [beforePolicy] [afterPolicy] [context.json]");
  process.exit(2);
}

const beforeSource = fs.readFileSync(beforePath, "utf8");
const afterSource = fs.readFileSync(afterPath, "utf8");
const context = contextPath ? JSON.parse(fs.readFileSync(contextPath, "utf8")) : {};
const report = evaluatePullRequestChange(beforeSource, afterSource, { beforePolicy, afterPolicy, context });

console.log(formatPullRequestGate(report));
console.log(JSON.stringify(report, null, 2));
process.exit(report.passed ? 0 : 1);
