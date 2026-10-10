import fs from "node:fs";
import path from "node:path";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createEvidenceShards, recoverEvidenceShards, repairEvidenceShare } from "../runtime/evidenceShards.js";

const [action, ...args] = process.argv.slice(2);
const read = file => JSON.parse(fs.readFileSync(file, "utf8"));
const write = (file, value) => fs.writeFileSync(file, `${canonicalJSONStringify(value)}\n`, { flag: "wx" });

try {
  if (action === "create" && args.length === 3) {
    const [handoffPath, trustPath, directory] = args;
    const shares = createEvidenceShards(read(handoffPath), read(trustPath));
    fs.mkdirSync(directory);
    const files = shares.map((share, index) => {
      const file = path.join(directory, `share-${index}.json`);
      write(file, share);
      return file;
    });
    process.stdout.write(`${JSON.stringify({ created: true, files, payload_sha512: shares[0].payload_sha512 }, null, 2)}\n`);
  } else if (action === "repair" && args.length === 4) {
    const [firstPath, secondPath, trustPath, destination] = args;
    const result = repairEvidenceShare([read(firstPath), read(secondPath)], read(trustPath));
    if (!result.repaired) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      process.exitCode = 1;
    } else {
      write(destination, result.share);
      const { share, ...report } = result;
      process.stdout.write(`${JSON.stringify({ ...report, destination }, null, 2)}\n`);
    }
  } else if (action === "recover" && (args.length === 4 || args.length === 5)) {
    const sharePaths = args.slice(0, -2);
    const [trustPath, destination] = args.slice(-2);
    const result = recoverEvidenceShards(sharePaths.map(read), read(trustPath));
    if (!result.recovered) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      process.exitCode = 1;
    } else {
      write(destination, result.migration);
      const { migration, ...report } = result;
      process.stdout.write(`${JSON.stringify({ ...report, destination }, null, 2)}\n`);
    }
  } else {
    process.stderr.write("Usage: node scripts/evidence-shards.mjs create <handoff.json> <trusted-policy.json> <new-directory>\n" +
      "       node scripts/evidence-shards.mjs recover <share-a.json> <share-b.json> [share-c.json] <trusted-policy.json> <new-handoff.json>\n" +
      "       node scripts/evidence-shards.mjs repair <share-a.json> <share-b.json> <trusted-policy.json> <new-share.json>\n");
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
