import test from "node:test";
import assert from "node:assert/strict";
import {
  createDecisionCache,
  createDeploymentFirewall,
  createStreamingInterfaceFirewall,
  evaluateInterfaceBatch
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

test("a cached shadow decision cannot turn a later enforced suppression into an allow", () => {
  const cache = createDecisionCache();
  const firewall = createDeploymentFirewall({ cache, profile: "calm_default" });
  const shadow = firewall.shadow(suppressedIntent, { timestamp: fixed });
  const enforced = firewall.enforce(suppressedIntent, { timestamp: fixed });
  assert.deepEqual([shadow.mode, shadow.aml_allowed, shadow.effective_allowed], ["shadow", false, true]);
  assert.deepEqual([enforced.mode, enforced.aml_allowed, enforced.effective_allowed], ["enforce", false, false]);
  assert.equal(enforced.cache.hit, false);
  assert.equal(firewall.enforce(suppressedIntent, { timestamp: fixed }).cache.hit, true);
  assert.equal(firewall.shadow(suppressedIntent, { timestamp: fixed }).cache.hit, true);

  const otherFirewall = createDeploymentFirewall({ cache, profile: "calm_default" });
  const changedFailureMode = otherFirewall.enforce(suppressedIntent, {
    timestamp: fixed, failure_mode: "open"
  });
  assert.equal(changedFailureMode.cache.hit, false);
  assert.equal(changedFailureMode.failure_mode, "open");
  assert.equal(changedFailureMode.effective_allowed, false);
});

test("a manual cache key cannot alias another intent, context, or audit stream", () => {
  const cache = createDecisionCache();
  const firewall = createDeploymentFirewall({ cache, profile: "calm_default" });
  const options = { timestamp: fixed, cache_key: "operator-batch" };
  const allowed = firewall.enforce(allowedIntent, options);
  const suppressed = firewall.enforce(suppressedIntent, options);
  assert.equal(suppressed.cache.hit, false);
  assert.equal(suppressed.effective_allowed, false);
  assert.notEqual(allowed.cache.key, suppressed.cache.key);

  const first = firewall.enforce(allowedIntent, { ...options, stream_id: "stream-a" });
  const second = firewall.enforce(allowedIntent, { ...options, stream_id: "stream-b" });
  assert.equal(first.cache.hit, false);
  assert.equal(second.cache.hit, false);
  assert.notEqual(first.result.receipt.receipt_sha256, second.result.receipt.receipt_sha256);
  assert.equal(firewall.enforce(allowedIntent, { ...options, stream_id: "stream-a" }).cache.hit, true);

  const changedContext = firewall.enforce(allowedIntent, {
    ...options, context: { privacy_consent: false }
  });
  assert.equal(changedContext.cache.hit, false);
  assert.notEqual(changedContext.cache.key, allowed.cache.key);
});

test("manual keys without fixed time never reuse time-dependent receipts", () => {
  const cache = createDecisionCache();
  const firewall = createDeploymentFirewall({ cache });
  firewall.enforce(allowedIntent, { cache_key: "same" });
  firewall.enforce(allowedIntent, { cache_key: "same" });
  assert.equal(cache.stats().size, 0);
});

test("cached evaluation uses the exact input snapshot represented by its key", () => {
  const cache = createDecisionCache();
  const firewall = createDeploymentFirewall({ cache, profile: "calm_default" });
  let reads = 0;
  const changing = structuredClone(allowedIntent);
  Object.defineProperty(changing.nodes[0].properties, "attention_cost", {
    enumerable: true,
    get() { reads++; return reads === 1 ? 1 : 5; }
  });
  const first = firewall.enforce(changing, { timestamp: fixed });
  assert.equal(reads, 1);
  assert.equal(first.aml_allowed, true);
  assert.equal(first.result.receipt.intent.nodes[0].properties.attention_cost, 1);
  const same = firewall.enforce(allowedIntent, { timestamp: fixed });
  assert.equal(same.cache.hit, true);
  assert.equal(same.effective_allowed, first.effective_allowed);
});

test("an optional cache outage cannot replace a computed denial with failure-open", () => {
  const unavailable = { get() { throw new Error("cache unavailable"); },
    set() { throw new Error("cache unavailable"); } };
  const firewall = createDeploymentFirewall({ cache: unavailable, failure_mode: "open",
    profile: "calm_default" });
  const result = firewall.enforce(suppressedIntent, { timestamp: fixed });
  assert.equal(result.aml_allowed, false);
  assert.equal(result.effective_allowed, false);
  assert.equal(result.evaluation_error, null);
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

test("batch firewall preserves per-intent evidence and aggregate outcome", () => {
  const batch = evaluateInterfaceBatch([allowedIntent, suppressedIntent], {
    mode: "enforce",
    profile: "calm_default",
    timestamp: fixed,
    max_items: 10
  });
  assert.equal(batch.total, 2);
  assert.equal(batch.aml_allowed, 1);
  assert.equal(batch.aml_suppressed, 1);
  assert.equal(batch.evaluation_errors, 0);
  assert.equal(batch.effective_allowed, 1);
  assert.equal(typeof batch.results[0].receipt_sha256, "string");
  assert.equal(typeof batch.results[1].receipt_sha256, "string");
});

test("batch firewall enforces explicit size bound", () => {
  assert.throws(
    () => evaluateInterfaceBatch([allowedIntent, suppressedIntent], { max_items: 1, timestamp: fixed }),
    /AML_BATCH_LIMIT_EXCEEDED/
  );
});
