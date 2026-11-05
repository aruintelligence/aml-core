#!/usr/bin/env node
// Project-authored controlled provider fault fixture. No external operation.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { planAction } from "./boundary.mjs";
import { createFileOneShotGrants } from "./file-one-shot-grants.mjs";
import { createProviderExecutionState } from "./provider-execution-state.mjs";

const worker = fileURLToPath(new URL("./local-provider-worker.mjs", import.meta.url));
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const runWorker = (mode, directory, id, digest, bytes = "") => spawnSync(process.execPath,
  [worker, mode, directory, id, digest, bytes], { encoding: "utf8", timeout: 20_000 });

export async function runLocalProviderRecovery({ mode = "lost_ack" } = {}) {
  if (!["lost_ack", "before_write", "ack"].includes(mode)) throw new TypeError("Invalid fault mode");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-local-provider-"));
  const effects = path.join(directory, "effects");
  fs.mkdirSync(effects, { mode: 0o700 });
  try {
    const grants = createFileOneShotGrants({ directory: path.join(directory, "grants") });
    await grants.initialize();
    const operationId = crypto.randomUUID();
    const proposal = { protocol: "aml-proposed-action/1", tool: "local:record",
      effect: "write", resource: "fixture:outbox", purpose: "Record one local effect",
      arguments: { body: "authorized fixture" } };
    const policy = { protocol: "aml-action-policy/1", rules: [
      { tool: proposal.tool, effect: proposal.effect, resource: proposal.resource,
        requires_approval: true }
    ] };
    const proposalSha256 = planAction(proposal, policy).proposal_sha256;
    const approval = await grants.issue(proposalSha256);
    const state = createProviderExecutionState({ operationId, proposalSha256 });
    state.record("approved", "fixture-host-approval"); // No human authentication.
    assert.equal(await grants.consume({ approval, proposal_sha256: proposalSha256 }), true);
    state.record("grant_consumed", approval.approval_id);
    const requestBytes = JSON.stringify({ operation_id: operationId,
      to: proposal.resource, body: proposal.arguments.body });
    const requestDigest = hash(requestBytes);
    state.record("request_initiated", requestDigest);
    const attempt = runWorker(mode, effects, operationId, requestDigest, requestBytes);
    if (attempt.error) throw attempt.error;
    assert.equal(attempt.status, mode === "lost_ack" ? 75 : mode === "before_write" ? 76 : 0);
    if (attempt.status !== 0) state.record("outcome_uncertain", `provider-child-exit:${attempt.status}`);
    else {
      state.record("provider_accepted", "fixture-acknowledgment");
      state.record("completed", "fixture-provider-record");
    }
    const before = state.snapshot();
    const replayAccepted = await grants.consume({ approval, proposal_sha256: proposalSha256 });
    // This is a fresh process reading provider-owned storage, not a second send.
    const recovery = runWorker("reconcile", effects, operationId, requestDigest);
    if (recovery.error || recovery.status !== 0) throw recovery.error || Error("Recovery failed");
    const providerRecord = JSON.parse(recovery.stdout).record;
    const matching = providerRecord?.protocol === "aml-local-provider-effect/1" &&
      providerRecord.operation_id === operationId && providerRecord.request_sha256 === requestDigest &&
      hash(JSON.stringify(providerRecord.request)) === requestDigest &&
      providerRecord.provider_status === "recorded";
    if (matching && before.state === "outcome_uncertain" && before.uncertain_from === "request_initiated") {
      state.record("provider_accepted", "fixture-recovery-record");
      state.record("completed", "fixture-recovery-record");
    }
    return { protocol: "aml-local-provider-recovery-report/1", mode, operation_id: operationId,
      proposal_sha256: proposalSha256, request_sha256: requestDigest,
      host_before_recovery: before.state, host_after_recovery: state.snapshot().state,
      independent_confirmation: false, provider_record_found: Boolean(matching),
      provider_effect_count: fs.readdirSync(effects).length,
      replay_accepted: replayAccepted, retry_attempted: false,
      provider_worker_exit_code: attempt.status };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  console.log(JSON.stringify(await runLocalProviderRecovery({ mode: process.argv[2] || "lost_ack" }), null, 2));
}
