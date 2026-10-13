import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import test from "node:test";
import { buildNextStep, firstRunAction, firstRunContinuation, firstRunPolicy, firstRunProposal, firstRunScenarioUrl, renderDecision } from "../docs/first-run.js";

const vectors = JSON.parse(readFileSync(new URL("../pilots/action-boundary/vectors.json", import.meta.url), "utf8"));

test("first-run agent scenarios match the published proposal, policy, decision, and digest", async () => {
  assert.deepEqual(firstRunPolicy.rules[0], vectors.policy.rules[0]);
  for (const [recipient, name] of [["team", "approved_route"], ["outside", "changed_destination"]]) {
    const expected = vectors.cases.find(item => item.name === name);
    assert.deepEqual(firstRunProposal(recipient), expected.proposal);
    const observed = await firstRunAction(recipient, webcrypto.subtle);
    assert.equal(observed.decision, expected.decision);
    assert.equal(observed.reason, expected.reason);
    assert.equal(observed.proposal_sha256, expected.proposal_sha256);
    assert.equal(observed.project_vector_matches, true);
    assert.equal(observed.tool_callbacks, 0);
  }
});

test("declared render values change at the exact threshold", () => {
  assert.equal(renderDecision(5, 1).decision, "suppress");
  assert.equal(renderDecision(5, 5).decision, "allow");
  assert.throws(() => renderDecision(11, 1), RangeError);
  assert.throws(() => firstRunProposal("another recipient"), RangeError);
});

test("the build handoff follows the boundary the visitor selected", () => {
  const agent = buildNextStep("action", 5, 1, "team");
  assert.equal(agent.href, "agent-start.html?recipient=team");
  assert.match(agent.hint, /guarded-tool-demo\.mjs$/);
  const interfaceStep = buildNextStep("render", 5, 6);
  assert.equal(interfaceStep.href, "quickstart.html?attention=5&restoration=6");
  assert.throws(() => buildNextStep("render", 11, 1), RangeError);
  assert.throws(() => buildNextStep("action", 5, 1, "unknown"), RangeError);
});

test("scenario state preserves the visitor's scroll target and copied links open the experiment", () => {
  const landing = "https://example.test/first-run.html";
  assert.equal(firstRunScenarioUrl(landing, "action", 5, 1, "outside"),
    "https://example.test/first-run.html?mode=action&recipient=outside");
  assert.equal(firstRunScenarioUrl(landing, "action", 5, 1, "team", true),
    "https://example.test/first-run.html?mode=action&recipient=team#experience");
  assert.equal(firstRunScenarioUrl(`${landing}#next`, "render", 5, 6),
    "https://example.test/first-run.html?mode=render&attention=5&restoration=6#next");
  assert.throws(() => firstRunScenarioUrl(landing, "render", 12, 1), RangeError);
});

test("first contact distinguishes an exact action match from approval and dispatch", async () => {
  const denied = firstRunContinuation("action", await firstRunAction("outside", webcrypto.subtle), 5, 1, "outside");
  const held = firstRunContinuation("action", await firstRunAction("team", webcrypto.subtle), 5, 1, "team");
  assert.match(denied.steps[0].value, /No matching destination/);
  assert.equal(denied.steps[1].value, "Not reached");
  assert.equal(denied.steps[2].value, "0 invocations");
  assert.equal(denied.probe.recipient, "team");
  assert.equal(held.steps[1].value, "Required; not issued");
  assert.equal(held.steps[2].value, "0 invocations");
  assert.equal(held.probe.recipient, "outside");
  assert.equal(firstRunContinuation("action", { decision: "requires_approval", project_vector_matches: false }, 5, 1, "team").probe, null);
});

test("first contact only describes an observed browser gate and offers the opposing input", () => {
  const suppressed = firstRunContinuation("render", { ...renderDecision(5, 1), gate_event: { render_allowed: false } }, 5, 1);
  assert.equal(suppressed.steps[1].value, "Hidden in this page");
  assert.deepEqual([suppressed.probe.attention, suppressed.probe.restoration], [5, 5]);
  const allowed = firstRunContinuation("render", { ...renderDecision(0, 0), gate_event: { render_allowed: true } }, 0, 0);
  assert.deepEqual([allowed.probe.attention, allowed.probe.restoration], [1, 0]);
  assert.equal(firstRunContinuation("render", renderDecision(5, 5), 5, 5).probe, null);
});
