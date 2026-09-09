import test from "node:test";
import assert from "node:assert/strict";

import {
  semanticDiff,
  policyDiff,
  policyMatrix,
  evaluatePolicyCanary
} from "../index.js";

const before = `transmission "duplicates" {
  engram dup {
    purpose: "Explain clearly"
    attention_cost: 5
    restoration_value: 5.5
  }
  engram dup {
    purpose: "Stable second node"
    attention_cost: 1
    restoration_value: 5
  }
}`;

const after = `transmission "duplicates" {
  engram dup {
    purpose: "Create urgency"
    attention_cost: 5
    restoration_value: 5.5
  }
  engram dup {
    purpose: "Stable second node"
    attention_cost: 1
    restoration_value: 5
  }
}`;

test("semantic diff cannot hide a changed node behind a duplicate identifier", () => {
  const report = semanticDiff(before, after);
  assert.equal(report.meaning_equivalent, false);
  assert.equal(report.identity_ambiguity_detected, true);
  assert.ok(report.ambiguous_identity_keys.some(entry => entry.key === "dup" && entry.count === 2));
  assert.ok(report.changed.some(change => change.key === "dup#1"));
  assert.ok(report.summary.changed > 0);
});

test("semantic diff preserves both duplicate nodes instead of overwriting one", () => {
  const report = semanticDiff(before, before);
  assert.equal(report.meaning_equivalent, true);
  assert.ok(report.unchanged.includes("dup#1"));
  assert.ok(report.unchanged.includes("dup#2"));
});

test("policy diff cannot hide a first duplicate decision behind the second", () => {
  const leftPolicy = {
    id: "left-test",
    evaluate(element) {
      return {
        policy_id: "left-test",
        render_allowed: true,
        attention_cost: element.attention_cost,
        restoration_value: element.restoration_value,
        rationale: "comparison-test"
      };
    }
  };
  let call = 0;
  const rightPolicy = {
    id: "right-test",
    evaluate(element) {
      call += 1;
      return {
        policy_id: "right-test",
        render_allowed: call !== 1,
        attention_cost: element.attention_cost,
        restoration_value: element.restoration_value,
        rationale: "comparison-test"
      };
    }
  };

  const report = policyDiff(before, leftPolicy, rightPolicy);
  assert.equal(report.identity_ambiguity_detected, true);
  assert.ok(report.ambiguous_identity_keys.some(entry => entry.key === "dup" && entry.count === 2));
  assert.equal(report.changed_decisions, 1);
  assert.equal(report.changes[0].key, "dup#1");
});

test("policy matrix evaluates every duplicate decision instead of findIndex collapsing them", () => {
  const source = `transmission "matrix-duplicates" {
    engram dup {
      purpose: "Stable first"
      attention_cost: 1
      restoration_value: 5
    }
    engram dup {
      purpose: "Policy-sensitive second"
      attention_cost: 5
      restoration_value: 5.5
    }
  }`;
  const report = policyMatrix(source, ["restorative_v1", "attention_conservative_v1"]);
  assert.equal(report.identity_ambiguity_detected, true);
  const duplicateRows = report.rows.filter(row => row.key.startsWith("dup#"));
  assert.equal(duplicateRows.length, 2);
  assert.equal(duplicateRows[0].disagreement, false);
  assert.equal(duplicateRows[1].disagreement, true);
  assert.equal(report.disagreements, 1);
});

test("policy canary cannot hide a changed first duplicate decision behind the second", () => {
  const intent = {
    transmission: "canary-duplicates",
    nodes: [
      {
        type: "engram",
        identifier: "dup",
        properties: {
          purpose: "Personalized first",
          attention_cost: 1,
          restoration_value: 5,
          collects_personal_data: true
        }
      },
      {
        type: "engram",
        identifier: "dup",
        properties: {
          purpose: "Stable second",
          attention_cost: 1,
          restoration_value: 5
        }
      }
    ]
  };

  const report = evaluatePolicyCanary(intent, {
    baseline_profile: "calm_default",
    candidate_profile: "human_first",
    context: { privacy_consent: false },
    timestamp: "1970-01-01T00:00:00.000Z"
  });
  assert.equal(report.identity_ambiguity_detected, true);
  assert.equal(report.total_decisions, 2);
  assert.equal(report.changed_decisions, 1);
  const first = report.changes.find(change => change.key === "dup#1");
  assert.equal(first.baseline_render_allowed, true);
  assert.equal(first.candidate_render_allowed, false);
});
