import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import { once } from "node:events";
import { createAmlHttpServer } from "../../server/httpServer.js";
import { getSourceState } from "../enterprise-30min/source-state.mjs";
import { applyVerifiedDecision, evaluateAndGate } from "./host-gate.mjs";

const load = (name) => JSON.parse(fs.readFileSync(new URL(`../enterprise-30min/${name}`, import.meta.url), "utf8"));
const allowedIntent = load("intent-allowed.json");
const sensitiveIntent = load("intent-sensitive.json");
const context = load("context-denied.json");
const profile = "human_first";
const token = randomBytes(32).toString("hex");
const server = createAmlHttpServer({ request_auth: { bearer_token: token },
  locked_policy: { profile, mode: "enforce", failure_mode: "closed", context } });

server.listen(0, "127.0.0.1");
await once(server, "listening");
const url = `http://127.0.0.1:${server.address().port}/v1/deployment/evaluate`;
const renderLog = [];
const render = async (html) => { renderLog.push(html); };
const request = async (intent, override = {}) => {
  const response = await fetch(url, { method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ intent, ...override }) });
  return { httpStatus: response.status, body: await response.json() };
};
const gate = (response, intent, callback = render) => applyVerifiedDecision({
  ...response, intent, profile, context, render: callback
});
const cases = [];

try {
  const allowed = await evaluateAndGate({ url, token, intent: allowedIntent, profile, context, render });
  cases.push({ id: "verified_allow", ...allowed });
  assert.equal(allowed.status, "rendered");
  assert.equal(renderLog.length, 1);
  assert.ok(typeof renderLog[0] === "string" && renderLog[0].length > 0);

  const allowedResponse = await request(allowedIntent);
  const sensitive = await evaluateAndGate({ url, token, intent: sensitiveIntent, profile, context, render });
  cases.push({ id: "consent_suppression", ...sensitive });
  assert.deepEqual([sensitive.status, sensitive.reason, renderLog.length], ["blocked", "policy_suppressed", 1]);

  const sensitiveResponse = await request(sensitiveIntent);

  const tampered = structuredClone(allowedResponse);
  tampered.body.receipt.selected_render.html += "<!-- changed after evaluation -->";
  const changedReceipt = await gate(tampered, allowedIntent);
  cases.push({ id: "changed_receipt", ...changedReceipt });
  assert.deepEqual([changedReceipt.status, changedReceipt.reason, renderLog.length], ["blocked", "receipt_invalid", 1]);

  const swapped = await gate(allowedResponse, sensitiveIntent);
  cases.push({ id: "valid_receipt_for_other_intent", ...swapped });
  assert.deepEqual([swapped.status, swapped.reason, renderLog.length], ["blocked", "receipt_binding_mismatch", 1]);

  const inconsistent = structuredClone(allowedResponse);
  inconsistent.body.effective_allowed = false;
  const changedDecision = await gate(inconsistent, allowedIntent);
  cases.push({ id: "changed_decision", ...changedDecision });
  assert.deepEqual([changedDecision.status, changedDecision.reason, renderLog.length], ["blocked", "decision_mismatch", 1]);

  const shadowLike = structuredClone(sensitiveResponse);
  shadowLike.body.mode = "shadow";
  shadowLike.body.effective_allowed = true;
  const shadowResponse = await gate(shadowLike, sensitiveIntent);
  cases.push({ id: "shadow_response", ...shadowResponse });
  assert.deepEqual([shadowResponse.status, shadowResponse.reason, renderLog.length],
    ["blocked", "unexpected_deployment_policy", 1]);

  const override = await request(sensitiveIntent, { mode: "shadow" });
  const callerPolicy = await gate(override, sensitiveIntent);
  cases.push({ id: "caller_policy_override", http_status: override.httpStatus, ...callerPolicy });
  assert.deepEqual([override.httpStatus, override.body.error, callerPolicy.status, renderLog.length],
    [403, "policy_override_forbidden", "blocked", 1]);

  const invalidIntent = { transmission: "invalid", nodes: [{ type: "not a valid type", properties: {} }] };
  const invalid = await evaluateAndGate({ url, token, intent: invalidIntent, profile, context, render });
  cases.push({ id: "evaluation_error", ...invalid });
  assert.deepEqual([invalid.status, invalid.reason, renderLog.length], ["blocked", "http_evaluation_unavailable", 1]);

  const outage = await evaluateAndGate({ url, token, intent: allowedIntent, profile, context, render,
    fetchImpl: async () => { throw new Error("simulated connection loss"); } });
  cases.push({ id: "transport_failure", ...outage });
  assert.deepEqual([outage.status, outage.reason, renderLog.length], ["blocked", "transport_or_response_error", 1]);

  const partialRender = await gate(allowedResponse, allowedIntent, async (html) => {
    renderLog.push(html);
    throw new Error("simulated host callback failure after entry");
  });
  cases.push({ id: "render_callback_uncertain", ...partialRender });
  assert.deepEqual([partialRender.status, partialRender.render_attempted, renderLog.length], ["unknown", true, 2]);

  process.stdout.write(`${JSON.stringify({ protocol: "aml-enterprise-http-gate-pilot/1",
    provenance: "project-authored localhost demonstration", ...getSourceState(), passed: true, cases,
    render_callback_entries: renderLog.length,
    claim_boundary: "Local callback entries only; no production UI, external customer, or independent validation." }, null, 2)}\n`);
} finally {
  server.close();
  await once(server, "close");
}
