import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { repairEvidenceShare } from "../runtime/evidenceShards.js";
import { runEvidenceDrill } from "../runtime/evidenceDrill.js";

const vector = new URL("../independent/vectors/shards-v1/", import.meta.url);
const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(new URL(`share-${index}.json`, vector))));
const policy = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/trusted-policy.json", import.meta.url)));

test("each missing shard is reconstructed byte for byte and all pairs pass", () => {
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const originals = pair.map(index => shares[index]);
    const result = repairEvidenceShare(originals, policy);
    assert.equal(result.repaired, true, result.reason);
    assert.equal(result.verified_pairs, 3);
    assert.equal(canonicalJSONStringify(result.share), canonicalJSONStringify(shares[result.missing_index]));
    assert.equal(runEvidenceDrill(shares.map((share, index) => index === result.missing_index ? result.share : share), policy).ready, true);
    assert.deepEqual(originals, pair.map(index => shares[index]));
  }
});

test("repair refuses stale policy, duplicate index, damaged survivor, and missing accepted head", () => {
  assert.equal(repairEvidenceShare(shares.slice(0, 2), { ...policy, accepted_head: undefined }).reason,
    "external_accepted_head_required");
  assert.equal(repairEvidenceShare([shares[0], shares[0]], policy).reason, "distinct_share_indices_required");
  assert.equal(repairEvidenceShare([shares[0], { ...shares[1], segment_base64: "damaged" }], policy).reason,
    "invalid_surviving_share");
  assert.equal(repairEvidenceShare([shares[0], shares[2]], { ...policy, accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } }).reason,
    "no_trusted_recovery_pair");
});
