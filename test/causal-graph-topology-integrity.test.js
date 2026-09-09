import test from "node:test";
import assert from "node:assert/strict";
import {
  createCausalEvent,
  createCausalExecutionGraph,
  verifyCausalExecutionGraph
} from "../index.js";

test("valid causal graph still verifies", () => {
  const root = createCausalEvent({ kind: "intent", payload: { id: 1 } });
  const child = createCausalEvent({ kind: "decision", parents: [root.event_hash], payload: { allowed: true } });
  const graph = createCausalExecutionGraph([root, child]);
  const result = verifyCausalExecutionGraph(graph);
  assert.equal(result.valid, true);
  assert.deepEqual(result.roots, [root.event_hash]);
  assert.deepEqual(result.heads, [child.event_hash]);
});

test("causal graph rejects event stored under the wrong map key", () => {
  const event = createCausalEvent({ kind: "intent", payload: { id: 1 } });
  const graph = createCausalExecutionGraph([event]);
  const forged = structuredClone(graph);
  forged.events = { ["0".repeat(64)]: event };
  forged.roots = ["0".repeat(64)];
  forged.heads = ["0".repeat(64)];

  const result = verifyCausalExecutionGraph(forged);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "event_key_mismatch");
});

test("causal graph rejects rewritten roots metadata", () => {
  const root = createCausalEvent({ kind: "intent" });
  const child = createCausalEvent({ kind: "decision", parents: [root.event_hash] });
  const graph = createCausalExecutionGraph([root, child]);
  const forged = { ...graph, roots: [child.event_hash] };
  assert.equal(verifyCausalExecutionGraph(forged).reason, "roots_mismatch");
});

test("causal graph rejects rewritten heads metadata", () => {
  const root = createCausalEvent({ kind: "intent" });
  const child = createCausalEvent({ kind: "decision", parents: [root.event_hash] });
  const graph = createCausalExecutionGraph([root, child]);
  const forged = { ...graph, heads: [root.event_hash] };
  assert.equal(verifyCausalExecutionGraph(forged).reason, "heads_mismatch");
});

test("causal graph verifier fails closed on malformed event containers", () => {
  const candidates = [
    { protocol: "aml-causal-graph/1", roots: [], heads: [], events: [] },
    { protocol: "aml-causal-graph/1", roots: null, heads: [], events: {} },
    { protocol: "aml-causal-graph/1", roots: [], heads: [], events: { bad: null } }
  ];
  for (const graph of candidates) {
    assert.doesNotThrow(() => verifyCausalExecutionGraph(graph));
    assert.equal(verifyCausalExecutionGraph(graph).valid, false);
  }
});
