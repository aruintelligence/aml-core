import test from "node:test";
import assert from "node:assert/strict";
import {
  createDecisionCache,
  createDeploymentFirewall,
  createStreamingInterfaceFirewall
} from "../index.js";

const allowedIntent = {
  transmission: "deployment_test",
  nodes: [{
    type: "message",
    identifier: "helpful",
    properties: {
      purpose: "Explain the next step",
      content: "Continue when ready",
      attention_cost: 1,
      restoration_value: 2
    }
  }]
};

const suppressedIntent = {
  transmission: "deployment_test",
  nodes: [{
    type: "message",
    identifier: "pressure",
    properties: {
      purpose: "Create urgency",
      content: "Act now",
      attention_cost: 5,
      restoration_value: 1
    }
  }]
};

const fixed = "2030-01-01T00:00:00.000Z";

test("deployment firewall enforce mode applies AML decision", () => {
  const firewall = createDeploymentFirewall({ mode: "enforce", profile: "calm_default" });
  const result = firewall.evaluate(suppressedIntent, { timestamp: fixed });
  assert.equal(result.aml_allowed, false);
  assert.equal(result.effective_allowed, false);
  assert.equal(result.would_suppress, true);
  assert.equal(result.evaluation_error, null);
});

test("deployment firewall shadow mode observes suppression without blocking rollout", () => {
  const firewall = createDeploymentFirewall({ mode: "shadow", profile: "calm_default" });
  const result = firewall.evaluate(suppressedIntent, { timestamp: fixed });
  assert.equal(result.aml_allowed, false);
  assert.equal(result.effective_allowed, true);
  assert.equal(result.would_suppress, true);
});

test("deployment firewall failure mode is explicit", () => {
  const invalidIntent = { transmission: "bad", nodes: [{ type: "not valid type", properties: {} }] };
  const closed = createDeploymentFirewall({ failure_mode: "closed" }).evaluate(invalidIntent, { timestamp: fixed });
  const open = createDeploymentFirewall({ failure_mode: "open" }).evaluate(invalidIntent, { timestamp: fixed });
  assert.equal(closed.effective_allowed, false);
  assert.equal(open.effective_allowed, true);
  assert.equal(closed.aml_allowed, null);
  assert.equal(open.aml_allowed, null);
  assert.match(closed.evaluation_error.message, /valid ĀML identifier/);
});

test("decision cache only caches automatically when evaluation time is fixed", () => {
  const cache = createDecisionCache({ max_entries: 8, ttl_ms: 60_000 });
  const firewall = createDeploymentFirewall({ cache, profile: "calm_default" });
  const first = firewall.evaluate(allowedIntent, { timestamp: fixed });
  const second = firewall.evaluate(allowedIntent, { timestamp: fixed });
  assert.equal(first.cache.hit, false);
  assert.equal(second.cache.hit, true);
  assert.equal(first.result.receipt.receipt_sha256, second.result.receipt.receipt_sha256);
  assert.equal(cache.stats().hits, 1);
});

test("decision cache refuses implicit dynamic-time caching", () => {
  const cache = createDecisionCache({ max_entries: 8, ttl_ms: 60_000 });
  const firewall = createDeploymentFirewall({ cache });
  firewall.evaluate(allowedIntent);
  firewall.evaluate(allowedIntent);
  assert.equal(cache.stats().size, 0);
});

test("streaming firewall evaluates nodes in order and preserves receipts", () => {
  const stream = createStreamingInterfaceFirewall({
    transmission: "assistant_stream",
    mode: "enforce",
    profile: "calm_default"
  });
  const one = stream.push(allowedIntent.nodes[0], { timestamp: fixed });
  const two = stream.push(suppressedIntent.nodes[0], { timestamp: fixed });
  assert.equal(one.sequence, 1);
  assert.equal(one.aml_allowed, true);
  assert.equal(two.sequence, 2);
  assert.equal(two.aml_allowed, false);
  assert.equal(typeof one.receipt_sha256, "string");
  const final = stream.finalize();
  assert.equal(final.total, 2);
  assert.equal(final.allowed, 1);
  assert.equal(final.suppressed, 1);
  assert.equal(final.finalized, true);
  assert.throws(() => stream.push(allowedIntent.nodes[0], { timestamp: fixed }), /AML_STREAM_ALREADY_FINALIZED/);
});

test("streaming firewall rejects duplicate identifiers", () => {
  const stream = createStreamingInterfaceFirewall({ transmission: "dup_test" });
  stream.push(allowedIntent.nodes[0], { timestamp: fixed });
  assert.throws(
    () => stream.push(allowedIntent.nodes[0], { timestamp: fixed }),
    /AML_STREAM_DUPLICATE_IDENTIFIER/
  );
});
