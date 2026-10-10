import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { repairEvidenceShare } from "../runtime/evidenceShards.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-repair-"));
const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(`independent/vectors/shards-v1/share-${index}.json`)));
const policy = JSON.parse(fs.readFileSync("independent/vectors/archive-v1/trusted-policy.json"));
const verifier = path.resolve("independent/python/repair_evidence_share.py");
const trustPath = path.join(directory, "trust.json");
fs.writeFileSync(trustPath, canonicalJSONStringify(policy));

function run(name, selected, expected, reason, trust = policy) {
  const paths = selected.map((share, index) => {
    const filename = path.join(directory, `${name}-${index}.json`);
    fs.writeFileSync(filename, canonicalJSONStringify(share));
    return filename;
  });
  const policyPath = path.join(directory, `${name}-policy.json`);
  fs.writeFileSync(policyPath, canonicalJSONStringify(trust));
  const output = path.join(directory, `${name}-repaired.json`);
  const args = [verifier, ...paths, policyPath, output];
  const result = spawnSync("python3", args, { encoding: "utf8" });
  if (result.error) throw result.error;
  const report = JSON.parse(result.stdout);
  assert.equal(result.status, expected ? 0 : 1, `${name}: ${result.stdout} ${result.stderr}`);
  assert.equal(report.repaired, expected, name);
  if (reason) assert.equal(report.reason, reason, name);
  if (!expected) assert.equal(fs.existsSync(output), false, name);
  return { report, output, args };
}

try {
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const selected = pair.map(index => shares[index]);
    const name = `pair-${pair.join("")}`;
    const { report, output, args } = run(name, selected, true);
    const js = repairEvidenceShare(selected, policy);
    assert.equal(report.missing_index, js.missing_index);
    assert.equal(report.payload_sha512, js.payload_sha512);
    assert.equal(report.verified_pairs, 3);
    assert.equal(fs.readFileSync(output, "utf8"), `${canonicalJSONStringify(js.share)}\n`);
    assert.equal(canonicalJSONStringify(js.share), canonicalJSONStringify(shares[js.missing_index]));
    const again = spawnSync("python3", args, { encoding: "utf8" });
    assert.equal(again.status, 1);
    assert.equal(JSON.parse(again.stdout).repaired, false);
  }
  run("duplicate", [shares[0], shares[0]], false, "distinct_share_indices_required");
  run("damage", [shares[0], { ...shares[1], segment_base64: "damaged" }], false, "invalid_surviving_share");
  run("stale", [shares[0], shares[2]], false, "no_trusted_recovery_pair",
    { ...policy, accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } });
  const { accepted_head, ...unbounded } = policy;
  run("unbounded", [shares[0], shares[2]], false, "external_accepted_head_required", unbounded);
  process.stdout.write(`${JSON.stringify({ protocol: "aml-repair-cross-runtime-check/1", passed: true,
    scenarios: ["all-three-pairs", "overwrite-refusal", "duplicate", "damage", "stale", "unbounded"] }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
