// Pin the v2 handoff without regenerating the already frozen v1 archive.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createEvidenceMigration, verifyEvidenceMigration } from "../runtime/evidenceMigration.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../independent/vectors/migration-v1");
const v1 = path.resolve(root, "../archive-v1");
const archive = JSON.parse(fs.readFileSync(path.join(v1, "archive.json"), "utf8"));
const policy = JSON.parse(fs.readFileSync(path.join(v1, "trusted-policy.json"), "utf8"));
const handoff = createEvidenceMigration(archive, policy);
if (!verifyEvidenceMigration(handoff, policy).verified) throw new Error("The handoff vector does not verify");
const content = `${canonicalJSONStringify(handoff)}\n`;
const expected = {
  protocol: "aml-evidence-migration-vector/1",
  migration_file_sha256: crypto.createHash("sha256").update(content).digest("hex"),
  migration_root_sha3_512: handoff.root_sha3_512,
  migration_root_sha512: handoff.root_sha512,
  source_archive_root_sha3_512: archive.root_sha3_512,
  expected: { verified: true, component_equivalent: true, renewal_count: 2, freshness_bound: true, policy_hint_trusted: false }
};
const files = { "migration.json": content, "expected.json": `${canonicalJSONStringify(expected)}\n` };
if (process.argv[2] === "--write") {
  fs.mkdirSync(root, { recursive: true });
  for (const [name, data] of Object.entries(files)) fs.writeFileSync(path.join(root, name), data);
} else if (process.argv.length !== 2) {
  throw new Error("Usage: node scripts/check-evidence-migration-vector.mjs [--write]");
} else {
  for (const [name, data] of Object.entries(files)) {
    if (!fs.existsSync(path.join(root, name)) || fs.readFileSync(path.join(root, name), "utf8") !== data) {
      throw new Error(`Migration vector drift: ${name}`);
    }
  }
}
process.stdout.write(`${JSON.stringify({ checked: Object.keys(files), migration_root_sha3_512: handoff.root_sha3_512 })}\n`);
