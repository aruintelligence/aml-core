import fs from "node:fs";
import path from "node:path";
import { compileSource } from "../index.js";

const manifestPath = path.resolve("conformance/manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

const failures = [];

for (const fixture of manifest.fixtures || []) {
  try {
    const source = fs.readFileSync(path.resolve(fixture.path), "utf8");
    const result = compileSource(source, { timestamp: "2026-01-01T00:00:00.000Z" });

    if (!Array.isArray(result.tokens)) failures.push(`${fixture.path}: tokens missing`);
    if (!result.ast) failures.push(`${fixture.path}: AST missing`);
    if (!result.amt) failures.push(`${fixture.path}: AMT missing`);
    if (!Array.isArray(result.renderDecisions)) failures.push(`${fixture.path}: render decisions missing`);
  } catch (error) {
    failures.push(`${fixture.path}: ${error.message}`);
  }
}

if (failures.length) {
  console.error("ĀML conformance check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`ĀML conformance check passed across ${manifest.fixtures.length} published fixtures.`);