#!/usr/bin/env node
// Controlled host-owned function-tool integration. No network or email send.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { planAction } from "../pilots/action-boundary/boundary.mjs";
import { createGuardedToolExecute } from "../pilots/action-boundary/guarded-tool.mjs";
import { createFileOneShotGrants } from "../pilots/action-boundary/file-one-shot-grants.mjs";

const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "local_outbox.append", effect: "write", resource: "sandbox:outbox", requires_approval: true }
] };
const proposalFor = argumentsValue => ({ protocol: "aml-proposed-action/1",
  tool: "local_outbox.append", effect: "write", resource: argumentsValue.destination,
  purpose: "Append one local test record", arguments: argumentsValue });

export async function runLocalOutboxReference() {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "aml-local-outbox-"));
  const outbox = path.join(temp, "outbox.ndjson");
  const grants = createFileOneShotGrants({ directory: path.join(temp, "grants") });
  let calls = 0;
  const gate = approval => createGuardedToolExecute({
    tool: "local_outbox.append", effect: "write", purpose: "Append one local test record",
    resourceFor: args => args.destination, policy,
    requestApproval: async () => approval,
    consumeApproval: input => grants.consume(input),
    execute: async args => {
      calls++;
      await fs.appendFile(outbox, JSON.stringify({ body: args.body }) + "\n");
      if (args.failAfterWrite) throw new Error("local callback failed after append");
      return { local_callback_returned: true };
    }
  });
  const count = async () => {
    try { return (await fs.readFile(outbox, "utf8")).trim().split("\n").length; }
    catch (error) { if (error.code === "ENOENT") return 0; throw error; }
  };
  try {
    const original = { destination: "sandbox:outbox", body: "approved record" };
    const denied = await gate({ approved: false })(original);
    const grant = await grants.issue(planAction(proposalFor(original), policy).proposal_sha256);
    const tampered = await gate(grant)({ ...original, body: "changed after approval" });
    const allowed = await gate(grant)(original);
    const replay = await gate(grant)(original);
    const afterReplay = await count();
    const uncertainArgs = { ...original, body: "callback error", failAfterWrite: true };
    const uncertainGrant = await grants.issue(planAction(proposalFor(uncertainArgs), policy).proposal_sha256);
    const uncertain = await gate(uncertainGrant)(uncertainArgs);
    const observedLocalRecords = await count();
    assert.deepEqual([denied.receipt.execution_status, tampered.receipt.execution_status,
      allowed.receipt.execution_status, replay.receipt.execution_status,
      uncertain.receipt.execution_status], ["blocked", "blocked", "dispatched", "blocked", "unknown"]);
    assert.equal(afterReplay, 1);
    assert.equal(observedLocalRecords, 2);
    assert.equal(calls, 2);
    return { protocol: "aml-local-outbox-reference/1", evidence_level: "E2 project-authored local test",
      source: "function-tool wrapper plus private local grant store",
      cases: [
        { name: "user_denies", receipt: denied.receipt, local_records_after_case: 0 },
        { name: "payload_changed", receipt: tampered.receipt, local_records_after_case: 0 },
        { name: "approved", receipt: allowed.receipt, local_records_after_case: 1 },
        { name: "replayed_grant", receipt: replay.receipt, local_records_after_case: afterReplay },
        { name: "callback_error_after_write", receipt: uncertain.receipt,
          local_records_after_case: observedLocalRecords }
      ],
      callback_count: calls,
      local_observation_sha256: crypto.createHash("sha256")
        .update(await fs.readFile(outbox)).digest("hex"),
      limitations: "No real model, authenticated human UI, external provider, distributed store or provider confirmation." };
  } finally { await fs.rm(temp, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runLocalOutboxReference().then(x => console.log(JSON.stringify(x, null, 2)))
    .catch(error => { console.error(error); process.exitCode = 1; });
}
