import test from "node:test";
import assert from "node:assert/strict";
import { createProofCarryingInterface, verifyProofCarryingInterface } from "../index.js";

test("proof-carrying interface binds output and accountability artifacts", () => {
  const html = "<main>hello</main>";
  const receipt = { type: "receipt", id: "r1" };
  const passport = { type: "passport", profile: "human_first" };
  const claim = { type: "claim", level: "federated" };

  const manifest = createProofCarryingInterface({
    html,
    receipt,
    policy_passport: passport,
    conformance_claim: claim
  });

  assert.equal(verifyProofCarryingInterface(manifest, {
    html,
    receipt,
    policy_passport: passport,
    conformance_claim: claim
  }).valid, true);
});

test("proof-carrying interface rejects mutated output or artifacts", () => {
  const html = "<main>hello</main>";
  const receipt = { id: "r1" };
  const manifest = createProofCarryingInterface({ html, receipt });

  assert.equal(verifyProofCarryingInterface(manifest, { html: "<main>changed</main>", receipt }).valid, false);
  assert.equal(verifyProofCarryingInterface(manifest, { html, receipt: { id: "r2" } }).valid, false);
});

test("proof verifier fails closed when manifest canonicalization is invalid", () => {
  const manifest = {
    type: "aml-proof-carrying-interface/1",
    output_sha256: "x",
    receipt_sha256: null,
    policy_passport_sha256: null,
    conformance_claim_sha256: null,
    provenance_sha256: null,
    causal_graph_sha256: null,
    hostile: 1n,
    manifest_sha256: "x"
  };

  assert.doesNotThrow(() => verifyProofCarryingInterface(manifest, { html: "<main>hello</main>" }));
  assert.deepEqual(verifyProofCarryingInterface(manifest, { html: "<main>hello</main>" }), {
    valid: false,
    reason: "invalid_manifest"
  });
});

test("proof verifier fails closed when supplied artifact canonicalization is invalid", () => {
  const html = "<main>hello</main>";
  const receipt = { id: "r1" };
  const manifest = createProofCarryingInterface({ html, receipt });
  const hostileReceipt = { id: "r1", hostile: 1n };

  assert.doesNotThrow(() => verifyProofCarryingInterface(manifest, { html, receipt: hostileReceipt }));
  assert.deepEqual(verifyProofCarryingInterface(manifest, { html, receipt: hostileReceipt }), {
    valid: false,
    reason: "receipt_sha256_invalid"
  });
});

test("proof verifier preserves missing-artifact mismatch semantics", () => {
  const html = "<main>hello</main>";
  const manifest = createProofCarryingInterface({ html, receipt: { id: "r1" } });
  const result = verifyProofCarryingInterface(manifest, { html });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "receipt_sha256_mismatch");
});
