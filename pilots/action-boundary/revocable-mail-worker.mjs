// Test-only separate host worker. All callbacks append to a local fixture log.
import fs from "node:fs";
import path from "node:path";
import { createFileRevocationHandoff } from "./file-revocation-handoff.mjs";
import { createRevocablePreparedMailToolExecute } from "./revocable-prepared-mail-tool.mjs";
import { mailTargetResource } from "./mail-target-manifest.mjs";

const [directory, operationId] = process.argv.slice(2);
const request = { to: "team@example.test", subject: "Release", body: "Approved text" };
const policy = { protocol: "aml-action-policy/1", rules: [{ tool: "send_message",
  effect: "send", resource: mailTargetResource(request).resource, requires_approval: true }] };
const send = createRevocablePreparedMailToolExecute({
  authority: createFileRevocationHandoff({ directory }),
  tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a", audience: "mail-service",
  purpose: "Send release", operationIdFor: () => operationId,
  getPolicy: () => policy, prepare: args => args,
  requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
  execute: () => {
    fs.appendFileSync(path.join(directory, "effects.log"), "send\n");
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 80);
    return { simulated: true };
  }
});
const result = await send(request);
process.stdout.write(JSON.stringify({ status: result.receipt.execution_status,
  reason: result.receipt.reason, dispatch_count: result.dispatch_count }) + "\n");
