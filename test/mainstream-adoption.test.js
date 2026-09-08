import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  createInterfaceFirewall,
  evaluateAccountableProps,
  viewMeaning,
  evaluatePullRequestChange
} from "../index.js";

const canonicalIntent = {
  transmission: "mainstream_test",
  nodes: [{
    type: "message",
    identifier: "welcome",
    properties: {
      purpose: "Help the user understand the interface",
      content: "Welcome",
      attention_cost: 1,
      restoration_value: 2
    }
  }]
};

test("Interface Firewall enforces canonical AI intent and returns proof surfaces", () => {
  const firewall = createInterfaceFirewall({ profile: "human_first" });
  const result = firewall.enforce(canonicalIntent, { timestamp: "2026-01-01T00:00:00.000Z" });
  assert.equal(result.allowed, true);
  assert.equal(result.report.receipt_verification.verified, true);
  assert.equal(result.report.provenance_verification.verified, true);
  assert.equal(result.report.accessibility.protocol, "ĀML Accessibility Audit Report");
});

test("React adapter maps friendly props into the accountable pipeline", () => {
  const result = evaluateAccountableProps({
    id: "pricing",
    purpose: "Explain pricing",
    content: "Simple pricing",
    attentionCost: 1,
    restorationValue: 2,
    policy: "calm_default"
  }, { timestamp: "2026-01-01T00:00:00.000Z" });
  assert.equal(result.allowed, true);
  assert.equal(result.receipt.protocol, "ĀML Accountable Execution Receipt");
});

test("View Meaning summarizes decisions without requiring raw JSON inspection", () => {
  const result = createInterfaceFirewall({ profile: "calm_default" }).enforce(canonicalIntent, { timestamp: "2026-01-01T00:00:00.000Z" });
  const report = viewMeaning(result.receipt);
  assert.equal(report.protocol, "ĀML View Meaning");
  assert.equal(report.summary.total_nodes >= 1, true);
  assert.equal(report.summary.suppressed, 0);
});

test("PR gate blocks high-risk semantic changes and stricter policy regressions", () => {
  const before = `transmission "gate" {\n  message "offer" {\n    purpose: "Explain an offer"\n    attention_cost: 1\n    restoration_value: 2\n  }\n}\n`;
  const after = `transmission "gate" {\n  message "offer" {\n    purpose: "Collect personal data for targeting"\n    attention_cost: 2\n    restoration_value: 4\n    collects_personal_data: true\n  }\n}\n`;
  const report = evaluatePullRequestChange(before, after, {
    beforePolicy: "calm_default",
    afterPolicy: "human_first",
    context: { privacy_consent: false },
    timestamp: "2026-01-01T00:00:00.000Z"
  });
  assert.equal(report.passed, false);
  assert.equal(report.blocking.high_risk_semantic_changes.length >= 1, true);
  assert.equal(report.blocking.policy_regressions.length >= 1, true);
});

test("Meaning Gate GitHub Action metadata exists", () => {
  assert.equal(fs.existsSync("actions/meaning-gate/action.yml"), true);
  assert.equal(fs.existsSync("scripts/meaning-gate.js"), true);
});
