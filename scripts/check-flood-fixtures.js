import fs from "node:fs";
import path from "node:path";
import { compileSource } from "../index.js";

const dir = path.resolve("conformance/flood");
const files = fs.readdirSync(dir).filter(name => name.endsWith(".aml")).sort();
let checked = 0;

for (const file of files) {
  const expected = file.startsWith("allow-") ? true : file.startsWith("suppress-") ? false : null;
  if (expected === null) continue;
  const source = fs.readFileSync(path.join(dir, file), "utf8");
  const result = compileSource(source, {
    timestamp: "2026-09-08T06:20:00.000Z",
    policy: "restorative_v1",
    context: {}
  });
  if (result.renderDecisions.length !== 1) {
    throw new Error(`${file}: expected exactly one render decision, got ${result.renderDecisions.length}`);
  }
  const actual = result.renderDecisions[0].render_allowed;
  if (actual !== expected) {
    throw new Error(`${file}: expected render_allowed=${expected}, got ${actual}`);
  }
  checked += 1;
}

if (checked !== 10) {
  throw new Error(`Expected 10 flood fixtures, verified ${checked}`);
}

console.log(JSON.stringify({ proof: "PASS", fixtures_verified: checked, allow: 5, suppress: 5 }, null, 2));
