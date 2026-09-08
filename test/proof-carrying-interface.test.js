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
