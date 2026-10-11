import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { evaluateContactContinuity } from "../pilots/field-contact-continuity.mjs";

const observation = JSON.parse(readFileSync(new URL("../experiments/2026-10-11/portland-contact-continuity/observations.json", import.meta.url)));
const labels = JSON.parse(readFileSync(new URL("../experiments/2026-10-11/portland-contact-continuity/labels.json", import.meta.url)));

test("candidate retains call and email in both observed production viewports", () => {
  const candidate = evaluateContactContinuity(observation, labels);
  assert.equal(candidate.continuity, "pass");
  assert.equal(candidate.decisions.find(x => x.element_id === "nav_phone").decision, "suppress");
  assert.deepEqual(candidate.screens.map(x => x.channels), [{ call: 2, email: 1 }, { call: 1, email: 1 }]);
});

test("over-suppression is caught only after the banner leaves the viewport", () => {
  const probe = evaluateContactContinuity(observation, labels, { adversarial: true });
  assert.equal(probe.continuity, "fail");
  assert.deepEqual(probe.screens.map(x => x.missing), [[], ["call"]]);
  assert.equal(probe.screens[1].channels.email, 1);
});

test("missing, duplicated, and unobserved labels cannot silently pass", () => {
  assert.throws(() => evaluateContactContinuity(observation, { ...labels, candidates: labels.candidates.slice(1) }), /invalid_field_labels/);
  assert.throws(() => evaluateContactContinuity(observation, { ...labels, candidates: [...labels.candidates, labels.candidates[0]] }), /invalid_field_labels/);
  assert.throws(() => evaluateContactContinuity({ ...observation, screens: [{ id: "bad", visible: ["unknown"] }] }, labels), /invalid_field_observation/);
});
