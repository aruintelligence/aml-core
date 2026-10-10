// Frozen physical-carrier bytes, derived from the frozen migration handoff.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createEvidenceShards, recoverEvidenceShards } from "../runtime/evidenceShards.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../independent/vectors/shards-v1");
const migration = JSON.parse(fs.readFileSync(path.resolve(root, "../migration-v1/migration.json"), "utf8"));
const trust = JSON.parse(fs.readFileSync(path.resolve(root, "../archive-v1/trusted-policy.json"), "utf8"));
const shares = createEvidenceShards(migration, trust);
for (const pair of [[0, 1], [0, 2], [1, 2]]) {
  if (!recoverEvidenceShards(pair.map(index => shares[index]), trust).recovered) throw new Error("The reference pair does not recover");
}
const files = Object.fromEntries(shares.map((share, index) => [`share-${index}.json`, `${canonicalJSONStringify(share)}\n`]));
const expected = {
  protocol: "aml-evidence-shards-vector/1",
  payload_sha512: shares[0].payload_sha512,
  migration_root_sha3_512: migration.root_sha3_512,
  share_file_sha256: Object.fromEntries(Object.entries(files).map(([name, content]) =>
    [name, crypto.createHash("sha256").update(content).digest("hex")])),
  expected: { recovered: true, shares_required: 2, policy_hint_trusted: false }
};
files["expected.json"] = `${canonicalJSONStringify(expected)}\n`;
if (process.argv[2] === "--write") {
  fs.mkdirSync(root, { recursive: true });
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content);
} else if (process.argv.length !== 2) {
  throw new Error("Usage: node scripts/check-evidence-shards-vector.mjs [--write]");
} else {
  for (const [name, content] of Object.entries(files)) {
    if (!fs.existsSync(path.join(root, name)) || fs.readFileSync(path.join(root, name), "utf8") !== content) {
      throw new Error(`Shard vector drift: ${name}`);
    }
  }
}
process.stdout.write(`${JSON.stringify({ checked: Object.keys(files), payload_sha512: expected.payload_sha512 })}\n`);
