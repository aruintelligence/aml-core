import test from "node:test";
import assert from "node:assert/strict";
import {
  createDisclosureCommitment,
  discloseClaims,
  verifyDisclosureProof
} from "../index.js";

test("valid selective disclosure proof still verifies", () => {
  const commitment = createDisclosureCommitment({ role: "admin", region: "us-west" });
  const proof = discloseClaims(commitment, ["role"]);
  assert.equal(verifyDisclosureProof(proof).valid, true);
});

test("selective disclosure verifier fails closed on non-array proof fields", () => {
  const commitment = createDisclosureCommitment({ role: "admin" });
  const proof = discloseClaims(commitment, ["role"]);
  for (const malformed of [
    { ...proof, disclosed: {} },
    { ...proof, hidden: {} },
    { ...proof, disclosed: null },
    { ...proof, hidden: null }
  ]) {
    assert.doesNotThrow(() => verifyDisclosureProof(malformed));
    assert.equal(verifyDisclosureProof(malformed).valid, false);
    assert.equal(verifyDisclosureProof(malformed).reason, "invalid_structure");
  }
});

test("selective disclosure verifier rejects malformed entries cleanly", () => {
  const commitment = createDisclosureCommitment({ role: "admin", region: "us-west" });
  const proof = discloseClaims(commitment, ["role"]);
  const malformed = { ...proof, hidden: [{ key: "region", leaf: "not-a-sha256" }] };
  assert.doesNotThrow(() => verifyDisclosureProof(malformed));
  assert.equal(verifyDisclosureProof(malformed).reason, "invalid_entry");
});

test("selective disclosure verifier rejects duplicate claim keys as ambiguous", () => {
  const commitment = createDisclosureCommitment({ role: "admin", region: "us-west" });
  const proof = discloseClaims(commitment, ["role"]);
  const duplicated = {
    ...proof,
    hidden: [...proof.hidden, { key: "role", leaf: proof.disclosed[0].leaf }]
  };
  const result = verifyDisclosureProof(duplicated);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "duplicate_key");
});

test("selective disclosure verifier rejects invalid roots without throwing", () => {
  const commitment = createDisclosureCommitment({ role: "admin" });
  const proof = discloseClaims(commitment, ["role"]);
  const result = verifyDisclosureProof({ ...proof, root: "bad-root" });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "invalid_root");
});
