import test from "node:test";
import assert from "node:assert/strict";
import { createCausalEvent, createCausalExecutionGraph, verifyCausalExecutionGraph } from "../index.js";

test("causal execution graph verifies multi-parent lineage", () => {
  const intent = createCausalEvent({ kind: "intent", payload: { purpose: "Explain choices" } });
  const policy = createCausalEvent({ kind: "policy-evaluation", payload: { profile: "human_first" }, parents: [intent.event_hash] });
  const accessibility = createCausalEvent({ kind: "accessibility-audit", payload: { reduced_motion: true }, parents: [intent.event_hash] });
  const render = createCausalEvent({
    kind: "render-decision",
    payload: { render_allowed: true },
    parents: [policy.event_hash, accessibility.event_hash]
  });

  const graph = createCausalExecutionGraph([intent, policy, accessibility, render]);
  const result = verifyCausalExecutionGraph(graph);
  assert.equal(result.valid, true);
  assert.equal(result.event_count, 4);
  assert.deepEqual(graph.heads, [render.event_hash]);
});

test("causal graph detects mutated event content", () => {
  const root = createCausalEvent({ kind: "intent", payload: { purpose: "A" } });
  const graph = createCausalExecutionGraph([root]);
  graph.events[root.event_hash].payload.purpose = "B";
  assert.equal(verifyCausalExecutionGraph(graph).reason, "event_hash_mismatch");
});

test("causal graph detects missing parent", () => {
  const child = createCausalEvent({ kind: "render-decision", payload: {}, parents: ["deadbeef"] });
  const graph = createCausalExecutionGraph([child]);
  assert.equal(verifyCausalExecutionGraph(graph).reason, "missing_parent");
});
