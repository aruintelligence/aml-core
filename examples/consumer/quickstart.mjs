import assert from "node:assert/strict";
import fs from "node:fs";
import { executeAccountableIntent, verifyExecutionReceipt } from "aml-core";

const intent = {
  transmission: "consumer_quickstart",
  nodes: [
    {
      type: "message",
      identifier: "pressure",
      properties: {
        purpose: "Create urgency",
        content: "Act now",
        attention_cost: 5,
        restoration_value: 1
      }
    },
    {
      type: "message",
      identifier: "continue",
      properties: {
        purpose: "Let the person continue",
        content: "Continue",
        attention_cost: 1,
        restoration_value: 3
      }
    }
  ]
};

const receipt = executeAccountableIntent(intent, {
  profile: "calm_default",
  context: {},
  timestamp: "2030-01-01T00:00:00.000Z"
});
const verification = verifyExecutionReceipt(receipt);
assert.equal(receipt.selected_render.allowed, 1);
assert.equal(receipt.selected_render.suppressed, 1);
assert.equal(verification.verified, true);

fs.writeFileSync("intent.json", `${JSON.stringify(intent, null, 2)}\n`);
fs.writeFileSync("context.json", "{}\n");
fs.writeFileSync("receipt.json", `${JSON.stringify(receipt, null, 2)}\n`);
console.log(JSON.stringify({
  protocol: "aml-consumer-quickstart/1",
  allowed: receipt.selected_render.allowed,
  suppressed: receipt.selected_render.suppressed,
  receipt_sha256: receipt.receipt_sha256,
  verified: verification.verified
}, null, 2));
