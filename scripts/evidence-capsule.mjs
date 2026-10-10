import fs from "node:fs";
import { createEvidenceCapsule, verifyEvidenceCapsule } from "../runtime/evidenceCapsule.js";

const [action, file] = process.argv.slice(2);
if (!["create", "verify"].includes(action) || !file) {
  process.stderr.write("Usage: node scripts/evidence-capsule.mjs <create|verify> <receipt-or-capsule.json>\n");
  process.exitCode = 2;
} else {
  try {
    const input = JSON.parse(fs.readFileSync(file, "utf8"));
    const result = action === "create" ? createEvidenceCapsule(input) : verifyEvidenceCapsule(input);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (action === "verify" && !result.verified) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
