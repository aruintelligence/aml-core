import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { executeAccountableIntent, verifyExecutionReceipt, viewMeaning } from "../../index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(fs.readFileSync(path.join(here, name), "utf8"));
const timestamp = "2026-09-08T00:00:00.000Z";

const scenarios = [
  {
    id: "calm_explanation",
    intent: load("intent-allowed.json"),
    context: load("context-denied.json")
  },
  {
    id: "sensitive_without_consent",
    intent: load("intent-sensitive.json"),
    context: load("context-denied.json")
  },
  {
    id: "sensitive_with_consent",
    intent: load("intent-sensitive.json"),
    context: load("context-allowed.json")
  }
];

const results = scenarios.map((scenario) => {
  const receipt = executeAccountableIntent(scenario.intent, {
    profile: "human_first",
    context: scenario.context,
    timestamp,
    stream_id: `enterprise-pilot-${scenario.id}`
  });
  const integrity = verifyExecutionReceipt(receipt);
  const meaning = viewMeaning(receipt);

  return {
    scenario: scenario.id,
    receipt_verified: integrity.verified,
    allowed: receipt.selected_render.allowed,
    suppressed: receipt.selected_render.suppressed,
    policy_id: receipt.selected_render.policy_id,
    receipt_sha256: receipt.receipt_sha256,
    meaning
  };
});

console.log(JSON.stringify({
  pilot: "ĀML Enterprise 30-Minute Pilot",
  profile: "human_first",
  results
}, null, 2));

if (results.some((result) => !result.receipt_verified)) process.exit(1);
if (results[0].allowed < 1) process.exit(2);
if (results[1].suppressed < 1) process.exit(3);
