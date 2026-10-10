import fs from "node:fs";
import { runEvidenceDrill } from "../runtime/evidenceDrill.js";

const [share0, share1, share2, policyPath] = process.argv.slice(2);
if (process.argv.length !== 6) {
  process.stderr.write("Usage: node scripts/evidence-drill.mjs <share-0.json> <share-1.json> <share-2.json> <trusted-policy.json>\n");
  process.exitCode = 2;
} else {
  const readShare = (file, index) => {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      return { index, unreadable: true };
    }
  };
  try {
    const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    const report = runEvidenceDrill([readShare(share0, 0), readShare(share1, 1), readShare(share2, 2)], policy);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.ready) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
