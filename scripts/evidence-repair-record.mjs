import fs from "node:fs";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createEvidenceRepairRecord, verifyEvidenceRepairRecord } from "../runtime/evidenceRepairRecord.js";

const [action, ...args] = process.argv.slice(2);
const read = file => JSON.parse(fs.readFileSync(file, "utf8"));
try {
  if (action === "create" && args.length === 5) {
    const [first, second, replacement, policy, destination] = args;
    const record = createEvidenceRepairRecord([read(first), read(second)], read(replacement), read(policy));
    fs.writeFileSync(destination, `${canonicalJSONStringify(record)}\n`, { flag: "wx" });
    process.stdout.write(`${JSON.stringify({ created: true, destination, root_sha3_512: record.root_sha3_512 }, null, 2)}\n`);
  } else if (action === "verify" && args.length === 5) {
    const [record, first, second, replacement, policy] = args;
    const result = verifyEvidenceRepairRecord(read(record), [read(first), read(second)], read(replacement), read(policy));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.verified) process.exitCode = 1;
  } else {
    process.stderr.write("Usage: node scripts/evidence-repair-record.mjs create <share-a.json> <share-b.json> <replacement.json> <trusted-policy.json> <new-record.json>\n" +
      "       node scripts/evidence-repair-record.mjs verify <record.json> <share-a.json> <share-b.json> <replacement.json> <trusted-policy.json>\n");
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
