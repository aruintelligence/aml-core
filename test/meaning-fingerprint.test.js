import test from "node:test";
import assert from "node:assert/strict";

import { meaningFingerprint, compareMeaningFingerprints, semanticDiff } from "../index.js";

const base = `transmission "demo" {
  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }
}`;

const reformatted = `// formatting and comments should not change meaning
transmission "demo" {

  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }

}`;

const changed = `transmission "demo" {
  engram card {
    purpose: "Create urgency"
    attention_cost: 2
    restoration_value: 5
  }
}`;

test("meaning fingerprint is stable across non-semantic source formatting", () => {
  const left = meaningFingerprint(base);
  const right = meaningFingerprint(reformatted);
  assert.equal(left.protocol, "aml-meaning-fingerprint/1");
  assert.equal(left.material_protocol, "aml-meaning-material/1");
  assert.equal(left.algorithm, "sha256");
  assert.match(left.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(left.fingerprint, right.fingerprint);
});

test("meaning fingerprint changes when declared meaning changes", () => {
  const left = meaningFingerprint(base);
  const right = meaningFingerprint(changed);
  assert.notEqual(left.fingerprint, right.fingerprint);
});

test("meaning equivalence report exposes both fingerprints", () => {
  const same = compareMeaningFingerprints(base, reformatted);
  assert.equal(same.equivalent, true);
  assert.equal(same.left.fingerprint, same.right.fingerprint);

  const different = compareMeaningFingerprints(base, changed);
  assert.equal(different.equivalent, false);
  assert.notEqual(different.left.fingerprint, different.right.fingerprint);
});

test("semantic diff is bound to the same meaning fingerprint contract", () => {
  const same = semanticDiff(base, reformatted);
  assert.equal(same.meaning_equivalent, true);
  assert.equal(same.left_meaning_fingerprint, same.right_meaning_fingerprint);
  assert.equal(same.fingerprint_protocol, "aml-meaning-fingerprint/1");

  const different = semanticDiff(base, changed);
  assert.equal(different.meaning_equivalent, false);
  assert.notEqual(different.left_meaning_fingerprint, different.right_meaning_fingerprint);
  assert.equal(different.summary.changed, 1);
});
