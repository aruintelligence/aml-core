import fs from "node:fs";
import { runEvidenceDrill } from "../runtime/evidenceDrill.js";
import { renderEvidenceDrillHtml } from "../runtime/evidenceDrillHtml.js";

const args = process.argv.slice(2);
if (args.length !== 5) {
  process.stderr.write("Usage: node scripts/evidence-drill-html.mjs <share-0.json> <share-1.json> <share-2.json> <trusted-policy.json> <new-report.html>\n");
  process.exitCode = 2;
} else {
  const readShare = (file, index) => {
    try { return JSON.parse(fs.readFileSync(file, "utf8")); }
    catch { return { index, unreadable: true }; }
  };
  try {
    const policy = JSON.parse(fs.readFileSync(args[3], "utf8"));
    const report = runEvidenceDrill(args.slice(0, 3).map(readShare), policy);
    fs.writeFileSync(args[4], renderEvidenceDrillHtml(report), { flag: "wx" });
    process.stdout.write(`${JSON.stringify({ created: true, destination: args[4], health: report.health,
      ready: report.ready, passed_pairs: report.passed_pairs, policy_sha256: report.policy_sha256 }, null, 2)}\n`);
    if (!report.ready) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
