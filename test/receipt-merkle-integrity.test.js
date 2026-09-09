import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  buildReceiptMerkleTree,
  createReceiptInclusionProof,
  verifyReceiptInclusionProof
} from "../index.js";

function leaf(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("valid Merkle inclusion proof still verifies", () => {
  const tree = buildReceiptMerkleTree([leaf("a"), leaf("b"), leaf("c"), leaf("d")]);
  const proof = createReceiptInclusionProof(tree, 2);
  const result = verifyReceiptInclusionProof(proof);
  assert.equal(result.verified, true);
  assert.equal(result.reason, null);
});

test("Merkle verifier rejects rewritten index metadata", () => {
  const tree = buildReceiptMerkleTree([leaf("a"), leaf("b"), leaf("c"), leaf("d")]);
  const proof = createReceiptInclusionProof(tree, 2);
  const forged = { ...proof, index: 3 };
  const result = verifyReceiptInclusionProof(forged);
  assert.equal(result.verified, false);
  assert.equal(result.reason, "index_path_mismatch");
});

test("Merkle verifier rejects invalid path positions", () => {
  const tree = buildReceiptMerkleTree([leaf("a"), leaf("b")]);
  const proof = createReceiptInclusionProof(tree, 0);
  const malformed = structuredClone(proof);
  malformed.proof[0].position = "sideways";
  assert.equal(verifyReceiptInclusionProof(malformed).reason, "invalid_position");
});

test("Merkle verifier fails closed on malformed proof structures", () => {
  const tree = buildReceiptMerkleTree([leaf("a"), leaf("b")]);
  const proof = createReceiptInclusionProof(tree, 0);
  for (const malformed of [
    { ...proof, proof: {} },
    { ...proof, proof: [null] },
    { ...proof, leaf: "not-a-hash" },
    { ...proof, root_sha256: "not-a-hash" },
    { ...proof, index: -1 },
    { ...proof, version: "9.9" }
  ]) {
    assert.doesNotThrow(() => verifyReceiptInclusionProof(malformed));
    assert.equal(verifyReceiptInclusionProof(malformed).verified, false);
  }
});
