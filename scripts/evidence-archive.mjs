import fs from "node:fs";
import path from "node:path";
import { createEvidenceArchive, verifyEvidenceArchive } from "../runtime/evidenceArchive.js";

const [action, ...args] = process.argv.slice(2);
const read = file => JSON.parse(fs.readFileSync(file, "utf8"));

try {
  if (action === "create" && args.length === 3) {
    const [capsule, renewals, policy] = args.map(read);
    process.stdout.write(`${JSON.stringify(createEvidenceArchive(capsule, renewals, policy), null, 2)}\n`);
  } else if ((action === "verify" || action === "extract") && args.length === (action === "verify" ? 2 : 3)) {
    const [archivePath, trustPath, destination] = args;
    const archive = read(archivePath);
    const result = verifyEvidenceArchive(archive, read(trustPath));
    if (!result.verified) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      process.exitCode = 1;
    } else if (action === "verify") {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      fs.mkdirSync(destination);
      for (const [name, value] of [
        ["capsule.json", archive.capsule_base64],
        ["renewals.json", archive.renewals_base64],
        ["policy-hint.json", archive.policy_hint_base64]
      ]) fs.writeFileSync(path.join(destination, name), Buffer.from(value, "base64"), { flag: "wx" });
      fs.writeFileSync(path.join(destination, "README.txt"), `${archive.readme}\n`, { flag: "wx" });
      process.stdout.write(`${JSON.stringify({ extracted: true, destination, ...result }, null, 2)}\n`);
    }
  } else {
    process.stderr.write("Usage: node scripts/evidence-archive.mjs create <capsule.json> <renewals.json> <policy.json>\n       node scripts/evidence-archive.mjs verify <archive.json> <trusted-policy.json>\n       node scripts/evidence-archive.mjs extract <archive.json> <trusted-policy.json> <new-directory>\n");
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
