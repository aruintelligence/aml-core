import fs from "node:fs";
import { assessEvidencePlacement } from "../runtime/evidencePlacement.js";

const args = process.argv.slice(2);
if (args.length !== 5) {
  process.stderr.write("Usage: node scripts/evidence-placement.mjs <share-0.json> <share-1.json> <share-2.json> <trusted-policy.json> <placement.json>\n");
  process.exitCode = 2;
} else {
  const read = file => JSON.parse(fs.readFileSync(file, "utf8"));
  const readShare = (file, index) => {
    try { return read(file); } catch { return { index, unreadable: true }; }
  };
  try {
    const report = assessEvidencePlacement(args.slice(0, 3).map(readShare), read(args[3]), read(args[4]));
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.ready) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
