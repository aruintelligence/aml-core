import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  createConsentLedger,
  grantConsent,
  revokeConsent,
  verifyConsentLedger,
  resolveConsent,
  createPolicyConsensus,
  buildReceiptMerkleTree,
  createReceiptInclusionProof,
  verifyReceiptInclusionProof,
  buildProvenanceGraph,
  verifyProvenanceGraph,
  executeAccountableIntent
} from "../index.js";

const sourceElement = { attention_cost: 2, restoration_value: 3 };

test("consent ledger supports grant, expiry, revocation, and tamper detection", () => {
  const ledger = createConsentLedger({ subject_id: "user-1", timestamp: "2026-01-01T00:00:00.000Z" });
  grantConsent(ledger, "personal_data", { timestamp: "2026-01-01T00:00:00.000Z", expires_at: "2026-01-02T00:00:00.000Z" });
  assert.equal(resolveConsent(ledger, "personal_data", { at: "2026-01-01T12:00:00.000Z" }).granted, true);
  assert.equal(resolveConsent(ledger, "personal_data", { at: "2026-01-03T00:00:00.000Z" }).granted, false);
  revokeConsent(ledger, "personal_data", { timestamp: "2026-01-01T18:00:00.000Z" });
  assert.equal(resolveConsent(ledger, "personal_data", { at: "2026-01-01T19:00:00.000Z" }).granted, false);
  assert.equal(verifyConsentLedger(ledger).verified, true);
  const mutated = structuredClone(ledger);
  mutated.events[0].scope = "different_scope";
  assert.equal(verifyConsentLedger(mutated).verified, false);
});

test("policy consensus preserves dissent instead of flattening disagreement", () => {
  const consensus = createPolicyConsensus(["restorative_v1", "attention_conservative_v1"], { strategy: "majority" });
  const result = consensus.evaluate(sourceElement, {});
  assert.equal(Array.isArray(result.votes), true);
  assert.equal(Array.isArray(result.dissent), true);
  assert.equal(result.votes.length, 2);
  assert.equal(result.dissent.length >= 1, true);
});

test("receipt Merkle batches prove inclusion and reject mutated proofs", () => {
  const leaves = ["a", "b", "c"].map(value => crypto.createHash("sha256").update(value).digest("hex"));
  const tree = buildReceiptMerkleTree(leaves);
  const proof = createReceiptInclusionProof(tree, 1);
  assert.equal(verifyReceiptInclusionProof(proof).verified, true);
  const mutated = structuredClone(proof);
  mutated.leaf = crypto.createHash("sha256").update("mutated").digest("hex");
  assert.equal(verifyReceiptInclusionProof(mutated).verified, false);
});

test("provenance graph is bound to an execution receipt", () => {
  const intent = {
    type: "message",
    id: "trust-test",
    purpose: "Show a useful message",
    content: "Hello",
    attention_cost: 1,
    restoration_value: 2
  };
  const receipt = executeAccountableIntent(intent, { timestamp: "2026-01-01T00:00:00.000Z" });
  const graph = buildProvenanceGraph(receipt);
  assert.equal(verifyProvenanceGraph(graph, receipt).verified, true);
  const mutated = structuredClone(graph);
  mutated.nodes[0].sha256 = "0".repeat(64);
  assert.equal(verifyProvenanceGraph(mutated, receipt).verified, false);
});
