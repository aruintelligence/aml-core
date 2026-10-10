import fs from "node:fs";
import { createEvidenceMigration, verifyEvidenceMigration } from "../runtime/evidenceMigration.js";

const [action, ...args] = process.argv.slice(2);
const read = file => JSON.parse(fs.readFileSync(file, "utf8"));

try {
  if (action === "create" && args.length === 2) {
    process.stdout.write(`${JSON.stringify(createEvidenceMigration(read(args[0]), read(args[1])), null, 2)}\n`);
  } else if ((action === "verify" || action === "recover") && args.length === (action === "verify" ? 2 : 3)) {
    const [migrationPath, trustPath, destination] = args;
    const migration = read(migrationPath);
    const result = verifyEvidenceMigration(migration, read(trustPath));
    if (!result.verified) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      process.exitCode = 1;
    } else if (action === "verify") {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      fs.writeFileSync(destination, `${Buffer.from(migration.source_archive_base64, "base64").toString("utf8")}\n`, { flag: "wx" });
      process.stdout.write(`${JSON.stringify({ recovered: true, destination, ...result }, null, 2)}\n`);
    }
  } else {
    process.stderr.write("Usage: node scripts/evidence-migration.mjs create <archive-v1.json> <trusted-policy.json>\n       node scripts/evidence-migration.mjs verify <handoff.json> <trusted-policy.json>\n       node scripts/evidence-migration.mjs recover <handoff.json> <trusted-policy.json> <new-archive-v1.json>\n");
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
