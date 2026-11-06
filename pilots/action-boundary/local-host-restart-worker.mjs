#!/usr/bin/env node
// Controlled host crash/restart fixture. Not a production durable journal.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { planAction } from "./boundary.mjs";
import { createFileOneShotGrants } from "./file-one-shot-grants.mjs";
import { createProviderExecutionState } from "./provider-execution-state.mjs";

const [mode, directory, fault] = process.argv.slice(2);
if (!["start", "recover"].includes(mode) || !path.isAbsolute(directory) ||
    (mode === "start" && !["lost_ack", "before_write"].includes(fault))) {
  throw Error("Invalid local host fixture invocation");
}
const journal = path.join(directory, "host-journal.json");
const effects = path.join(directory, "effects");
const provider = fileURLToPath(new URL("./local-provider-worker.mjs", import.meta.url));
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
function persist(value) {
  const temp = path.join(directory, `host-journal.${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(temp, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + "\n"); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(temp, journal);
  const dirfd = fs.openSync(directory, "r");
  try { fs.fsyncSync(dirfd); } finally { fs.closeSync(dirfd); }
}
function providerCall(kind, record, bytes = "") {
  return spawnSync(process.execPath, [provider, kind, effects, record.operation_id,
    record.request_sha256, bytes], { encoding: "utf8", timeout: 20_000 });
}
if (mode === "start") {
  fs.mkdirSync(effects, { mode: 0o700 });
  const grants = createFileOneShotGrants({ directory: path.join(directory, "grants") });
  await grants.initialize();
  const operationId = crypto.randomUUID();
  const proposal = { protocol: "aml-proposed-action/1", tool: "local:record", effect: "write",
    resource: "fixture:outbox", purpose: "Record one local effect",
    arguments: { body: "authorized fixture" } };
  const policy = { protocol: "aml-action-policy/1", rules: [{ tool: proposal.tool,
    effect: proposal.effect, resource: proposal.resource, requires_approval: true }] };
  const proposalSha256 = planAction(proposal, policy).proposal_sha256;
  const approval = await grants.issue(proposalSha256);
  const state = createProviderExecutionState({ operationId, proposalSha256 });
  const requestBytes = JSON.stringify({ operation_id: operationId,
    proposal_sha256: proposalSha256, to: proposal.resource, body: proposal.arguments.body });
  const record = { protocol: "aml-local-host-journal/1", operation_id: operationId,
    proposal_sha256: proposalSha256, approval, request_sha256: hash(requestBytes),
    request_bytes: requestBytes, events: [] };
  function advance(next, evidence) {
    state.record(next, evidence);
    record.events = state.snapshot().events;
    persist(record);
  }
  advance("approved", "fixture-host-approval");
  assert.equal(await grants.consume({ approval, proposal_sha256: proposalSha256 }), true);
  advance("grant_consumed", approval.approval_id);
  advance("request_initiated", record.request_sha256);
  const child = providerCall(fault, record, requestBytes);
  if (child.error) throw child.error;
  assert.equal(child.status, fault === "lost_ack" ? 75 : 76);
  // Exit without writing an acknowledgment/uncertainty state. The parent must
  // launch a fresh host process to reconstruct the journal and reconcile.
  process.exitCode = 77;
} else {
  const record = JSON.parse(fs.readFileSync(journal, "utf8"));
  if (record.protocol !== "aml-local-host-journal/1" ||
      hash(record.request_bytes) !== record.request_sha256 ||
      JSON.parse(record.request_bytes).operation_id !== record.operation_id ||
      JSON.parse(record.request_bytes).proposal_sha256 !== record.proposal_sha256 ||
      !/^[0-9a-f-]{36}$/i.test(record.approval?.approval_id)) {
    throw Error("Invalid host journal binding");
  }
  const issued = JSON.parse(fs.readFileSync(path.join(directory, "grants", "issued",
    `${record.approval.approval_id}.json`), "utf8"));
  if (issued.approval_id !== record.approval.approval_id ||
      issued.proposal_sha256 !== record.proposal_sha256 ||
      record.approval.proposal_sha256 !== record.proposal_sha256) {
    throw Error("Invalid host grant binding");
  }
  const state = createProviderExecutionState({ operationId: record.operation_id,
    proposalSha256: record.proposal_sha256 });
  for (const event of record.events) {
    if (state.snapshot().state !== event.from) throw Error("Invalid host event sequence");
    state.record(event.to, event.evidence_ref);
  }
  if (state.snapshot().state !== "request_initiated") throw Error("Unexpected restart state");
  const grants = createFileOneShotGrants({ directory: path.join(directory, "grants") });
  if (!await grants.verifyConsumed({ approval: record.approval,
    proposal_sha256: record.proposal_sha256 })) {
    throw Error("Missing or invalid grant consumption evidence");
  }
  state.record("outcome_uncertain", "host-restart-without-ack");
  const before = state.snapshot().state;
  const replayAccepted = await grants.consume({ approval: record.approval,
    proposal_sha256: record.proposal_sha256 });
  const child = providerCall("reconcile", record);
  if (child.error || child.status !== 0) throw child.error || Error("Provider read failed");
  const providerRecord = JSON.parse(child.stdout).record;
  const matching = providerRecord?.protocol === "aml-local-provider-effect/1" &&
    providerRecord.operation_id === record.operation_id &&
    providerRecord.request_sha256 === record.request_sha256 &&
    hash(JSON.stringify(providerRecord.request)) === record.request_sha256 &&
    providerRecord.provider_status === "recorded";
  if (matching) {
    state.record("provider_accepted", "fixture-provider-record");
    state.record("completed", "fixture-provider-record");
  }
  record.events = state.snapshot().events;
  persist(record);
  console.log(JSON.stringify({ protocol: "aml-local-host-restart-report/1",
    host_before_recovery: before, host_after_recovery: state.snapshot().state,
    provider_record_found: Boolean(matching), effect_count: fs.readdirSync(effects).length,
    replay_accepted: replayAccepted, retry_attempted: false,
    independent_confirmation: false }));
}
