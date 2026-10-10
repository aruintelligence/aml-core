import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { assessEvidencePlacement } from "../runtime/evidencePlacement.js";

const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(new URL(`../independent/vectors/shards-v1/share-${index}.json`, import.meta.url))));
const policy = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/trusted-policy.json", import.meta.url)));
const placement = JSON.parse(fs.readFileSync(new URL("../independent/vectors/placement-v1/placement.json", import.meta.url)));

test("frozen placement vector checks every declared single-domain loss", () => {
  const report = assessEvidencePlacement(shares, policy, placement);
  const expected = fs.readFileSync(new URL("../independent/vectors/placement-v1/expected.json", import.meta.url), "utf8");
  assert.equal(`${canonicalJSONStringify(report)}\n`, expected);
  assert.equal(report.health, "declared_resilient");
  assert.equal(report.scenarios.length, 9);
  assert.equal(report.failed_scenarios, 0);
});

test("shared site or custodian exposes a common failure despite a ready cryptographic drill", () => {
  const correlated = structuredClone(placement);
  correlated.shares[1].site = correlated.shares[0].site;
  correlated.shares[2].custodian = correlated.shares[0].custodian;
  const report = assessEvidencePlacement(shares, policy, correlated);
  assert.equal(report.drill_health, "ready");
  assert.equal(report.ready, false);
  assert.equal(report.health, "correlated");
  assert.equal(report.failed_scenarios, 2);
  assert.deepEqual(report.scenarios.filter(item => !item.recovered).map(item => item.dimension), ["site", "custodian"]);
});

test("unbounded trust, damaged copies, and incomplete manifest cannot pass", () => {
  const { accepted_head, ...unbounded } = policy;
  assert.equal(assessEvidencePlacement(shares, unbounded, placement).health, "unverified");
  const damaged = structuredClone(shares);
  damaged[0].segment_base64 = "broken";
  assert.equal(assessEvidencePlacement(damaged, policy, placement).health, "correlated");
  assert.equal(assessEvidencePlacement(shares, policy, { ...placement, shares: placement.shares.slice(0, 2) }).reason,
    "invalid_placement_manifest");
});
