import test from "node:test";
import assert from "node:assert/strict";
import {
  createDeploymentFirewall,
  createRolloutMonitor,
  evaluatePolicyCanary,
  evaluateRolloutCriteria
} from "../index.js";

const fixed = "2030-01-01T00:00:00.000Z";

const intent = {
  transmission: "rollout_test",
  nodes: [{
    type: "message",
    identifier: "offer",
    properties: {
      purpose: "Explain an offer",
      content: "Offer details",
      attention_cost: 2,
      restoration_value: 2
    }
  }]
};

const suppressIntent = {
  transmission: "rollout_test",
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

test("policy canary compares baseline and candidate receipts", () => {
  const result = evaluatePolicyCanary(intent, {
    baseline_profile: "calm_default",
    candidate_profile: "human_first",
    timestamp: fixed
  });
  assert.equal(result.protocol, "ĀML Policy Canary Result");
  assert.equal(result.total_decisions >= 1, true);
  assert.equal(typeof result.baseline.receipt_sha256, "string");
  assert.equal(typeof result.candidate.receipt_sha256, "string");
  assert.equal(Array.isArray(result.changes), true);
});

test("policy canary preserves changed decision direction", () => {
  const result = evaluatePolicyCanary({
    transmission: "privacy_canary",
    nodes: [{
      type: "message",
      identifier: "collect",
      properties: {
        purpose: "Collect optional personal data",
        attention_cost: 1,
        restoration_value: 4,
        collects_personal_data: true
      }
    }]
  }, {
    baseline_profile: "calm_default",
    candidate_profile: "privacy_first",
    context: { privacy_consent: false },
    timestamp: fixed
  });
  assert.equal(result.changed_decisions >= 1, true);
  assert.equal(result.candidate_new_suppressions >= 1, true);
});

test("rollout monitor summarizes shadow and enforce behavior without network transport", () => {
  const monitor = createRolloutMonitor({ max_records: 10 });
  const shadow = createDeploymentFirewall({ mode: "shadow", profile: "calm_default" });
  const enforce = createDeploymentFirewall({ mode: "enforce", profile: "calm_default" });

  monitor.record(shadow.evaluate(suppressIntent, { timestamp: fixed }), { label: "shadow-pressure" });
  monitor.record(enforce.evaluate(intent, { timestamp: fixed }), { label: "enforce-offer" });

  const summary = monitor.summary();
  assert.equal(summary.total, 2);
  assert.equal(summary.shadow_evaluations, 1);
  assert.equal(summary.enforced_evaluations, 1);
  assert.equal(summary.would_suppress, 1);
  assert.equal(summary.evaluation_errors, 0);
  assert.equal(monitor.records().length, 2);
});

test("rollout monitor retains a bounded record window", () => {
  const monitor = createRolloutMonitor({ max_records: 2 });
  const firewall = createDeploymentFirewall({ mode: "shadow", profile: "calm_default" });
  monitor.record(firewall.evaluate(intent, { timestamp: fixed }), { label: "one" });
  monitor.record(firewall.evaluate(intent, { timestamp: fixed }), { label: "two" });
  monitor.record(firewall.evaluate(intent, { timestamp: fixed }), { label: "three" });
  const records = monitor.records();
  assert.equal(records.length, 2);
  assert.equal(records[0].label, "two");
  assert.equal(records[1].label, "three");
});

test("rollout criteria only evaluate operator-supplied mechanical thresholds", () => {
  const monitor = createRolloutMonitor({ max_records: 10 });
  const shadow = createDeploymentFirewall({ mode: "shadow", profile: "calm_default" });
  monitor.record(shadow.evaluate(intent, { timestamp: fixed }), { recorded_at: fixed });
  monitor.record(shadow.evaluate(suppressIntent, { timestamp: fixed }), { recorded_at: fixed });

  const result = evaluateRolloutCriteria(monitor.summary(), {
    min_evaluations: 2,
    max_evaluation_error_rate: 0,
    max_aml_suppression_rate: 0.5,
    min_shadow_rate: 1
  });

  assert.equal(result.protocol, "ĀML Rollout Criteria Result");
  assert.equal(result.criteria_met, true);
  assert.match(result.claim_boundary, /does not prove safety, correctness, ethics, compliance, or production readiness/i);
});

test("rollout criteria report failed thresholds without converting them into policy truth", () => {
  const monitor = createRolloutMonitor({ max_records: 10 });
  const shadow = createDeploymentFirewall({ mode: "shadow", profile: "calm_default" });
  monitor.record(shadow.evaluate(suppressIntent, { timestamp: fixed }), { recorded_at: fixed });

  const result = evaluateRolloutCriteria(monitor.summary(), {
    min_evaluations: 10,
    max_aml_suppression_rate: 0.1
  });

  assert.equal(result.criteria_met, false);
  assert.equal(result.checks.filter(check => !check.passed).length, 2);
});

test("rollout criteria reject empty or invalid operator criteria", () => {
  const monitor = createRolloutMonitor({ max_records: 2 });
  const shadow = createDeploymentFirewall({ mode: "shadow", profile: "calm_default" });
  monitor.record(shadow.evaluate(intent, { timestamp: fixed }), { recorded_at: fixed });
  const summary = monitor.summary();
  assert.throws(() => evaluateRolloutCriteria(summary, {}), /At least one rollout criterion/);
  assert.throws(
    () => evaluateRolloutCriteria(summary, { max_evaluation_error_rate: 1.5 }),
    /between 0 and 1/
  );
});
