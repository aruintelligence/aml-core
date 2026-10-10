import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createEvidenceRepairRecord, verifyEvidenceRepairRecord } from "../runtime/evidenceRepairRecord.js";

const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(new URL(`../independent/vectors/shards-v1/share-${index}.json`, import.meta.url))));
const policy = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/trusted-policy.json", import.meta.url)));

test("a local repair record binds the survivors, replacement, policy, and accepted head", () => {
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const missing = [0, 1, 2].find(index => !pair.includes(index));
    const survivors = pair.map(index => shares[index]);
    const record = createEvidenceRepairRecord(survivors, shares[missing], policy);
    assert.equal(record.replacement_index, missing);
    assert.equal(record.verified_pairs, 3);
    assert.equal(verifyEvidenceRepairRecord(record, survivors.reverse(), shares[missing], policy).verified, true);
    assert.equal(verifyEvidenceRepairRecord({ ...record, policy_sha256: "0".repeat(64) }, survivors, shares[missing], policy).reason,
      "record_mismatch");
  }
});

test("different replacement, head, or survivor cannot reuse a repair record", () => {
  const record = createEvidenceRepairRecord([shares[0], shares[2]], shares[1], policy);
  assert.equal(verifyEvidenceRepairRecord(record, [shares[0], shares[2]], shares[0], policy).reason,
    "replacement_mismatch");
  const wrongHead = { ...policy, accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } };
  assert.equal(verifyEvidenceRepairRecord(record, [shares[0], shares[2]], shares[1], wrongHead).verified, false);
  assert.equal(verifyEvidenceRepairRecord(record, [shares[0], { ...shares[2], segment_base64: "bad" }], shares[1], policy).verified, false);
});

test("frozen repair record retains canonical wire bytes", () => {
  const expected = fs.readFileSync(new URL("../independent/vectors/repair-record-v1/record.json", import.meta.url), "utf8");
  const actual = createEvidenceRepairRecord([shares[0], shares[2]], shares[1], policy);
  assert.equal(`${canonicalJSONStringify(actual)}\n`, expected);
});
