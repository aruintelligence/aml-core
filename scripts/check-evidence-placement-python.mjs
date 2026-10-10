import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { assessEvidencePlacement } from "../runtime/evidencePlacement.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-placement-"));
const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(`independent/vectors/shards-v1/share-${index}.json`)));
const policy = JSON.parse(fs.readFileSync("independent/vectors/archive-v1/trusted-policy.json"));
const placement = JSON.parse(fs.readFileSync("independent/vectors/placement-v1/placement.json"));
const vector = fs.readFileSync("independent/vectors/placement-v1/expected.json", "utf8");
const verifier = path.resolve("independent/python/evidence_placement.py");

function compare(name, copies, trust, manifest) {
  const paths = copies.map((share, index) => {
    const file = path.join(directory, `${name}-share-${index}.json`);
    fs.writeFileSync(file, canonicalJSONStringify(share));
    return file;
  });
  const policyPath = path.join(directory, `${name}-policy.json`);
  const placementPath = path.join(directory, `${name}-placement.json`);
  fs.writeFileSync(policyPath, canonicalJSONStringify(trust));
  fs.writeFileSync(placementPath, canonicalJSONStringify(manifest));
  const js = assessEvidencePlacement(copies, trust, manifest);
  const result = spawnSync("python3", [verifier, ...paths, policyPath, placementPath], { encoding: "utf8" });
  if (result.error) throw result.error;
  assert.equal(result.status, js.ready ? 0 : 1, `${name}: ${result.stdout} ${result.stderr}`);
  assert.equal(canonicalJSONStringify(JSON.parse(result.stdout)), canonicalJSONStringify(js), name);
  return js;
}

try {
  assert.equal(`${canonicalJSONStringify(compare("independent", shares, policy, placement))}\n`, vector);
  const shared = structuredClone(placement);
  shared.shares[1].site = shared.shares[0].site;
  shared.shares[2].custodian = shared.shares[0].custodian;
  assert.equal(compare("correlated", shares, policy, shared).health, "correlated");
  const { accepted_head, ...unbounded } = policy;
  assert.equal(compare("unbounded", shares, unbounded, placement).health, "unverified");
  const damaged = structuredClone(shares);
  damaged[0].segment_base64 = "broken";
  assert.equal(compare("damaged", damaged, policy, placement).health, "correlated");
  assert.equal(compare("invalid", shares, policy, { ...placement, shares: placement.shares.slice(0, 2) }).health, "invalid");
  process.stdout.write(`${JSON.stringify({ protocol: "aml-placement-cross-runtime-check/1", passed: true,
    scenarios: ["independent", "correlated", "unbounded", "damaged", "invalid"] }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
