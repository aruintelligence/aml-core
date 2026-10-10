import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createEvidenceRepairRecord } from "../runtime/evidenceRepairRecord.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-repair-record-"));
const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(`independent/vectors/shards-v1/share-${index}.json`)));
const policy = JSON.parse(fs.readFileSync("independent/vectors/archive-v1/trusted-policy.json"));
const verifier = path.resolve("independent/python/evidence_repair_record.py");

function run(args, success = true) {
  const result = spawnSync("python3", [verifier, ...args], { encoding: "utf8" });
  if (result.error) throw result.error;
  assert.equal(result.status, success ? 0 : 1, `${result.stdout} ${result.stderr}`);
  return JSON.parse(result.stdout);
}

try {
  const trustPath = path.join(directory, "policy.json");
  fs.writeFileSync(trustPath, canonicalJSONStringify(policy));
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const missing = [0, 1, 2].find(index => !pair.includes(index));
    const paths = [0, 1, 2].map(index => {
      const file = path.join(directory, `share-${index}.json`);
      fs.writeFileSync(file, canonicalJSONStringify(shares[index]));
      return file;
    });
    const output = path.join(directory, `record-${missing}.json`);
    const record = createEvidenceRepairRecord(pair.map(index => shares[index]), shares[missing], policy);
    const created = run(["create", ...pair.map(index => paths[index]), paths[missing], trustPath, output]);
    assert.equal(created.root_sha3_512, record.root_sha3_512);
    assert.equal(fs.readFileSync(output, "utf8"), `${canonicalJSONStringify(record)}\n`);
    assert.equal(run(["verify", output, ...pair.map(index => paths[index]), paths[missing], trustPath]).verified, true);
    const changed = { ...record, policy_sha256: "0".repeat(64) };
    fs.writeFileSync(output, canonicalJSONStringify(changed));
    assert.equal(run(["verify", output, ...pair.map(index => paths[index]), paths[missing], trustPath], false).reason,
      "record_mismatch");
    assert.equal(run(["create", ...pair.map(index => paths[index]), paths[missing], trustPath, output], false).created, false);
  }
  process.stdout.write(`${JSON.stringify({ protocol: "aml-repair-record-cross-runtime-check/1", passed: true,
    scenarios: ["all-three-missing-indices", "tamper", "overwrite-refusal"] }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
