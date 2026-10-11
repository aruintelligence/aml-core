#!/usr/bin/env node
// Two child processes compete for the same host-owned grant. Output contains
// observed statuses, not a fabricated browser simulation or delivery claim.
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { planAction } from "./boundary.mjs";
import { createFileOneShotGrants } from "./file-one-shot-grants.mjs";

const proposal = { protocol: "aml-proposed-action/1", tool: "send_message",
  effect: "send", resource: "team@example.test", purpose: "Send a status update",
  arguments: { to: "team@example.test", body: "Build passed." } };
const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }
] };
const workerFile = new URL("./file-grant-worker.mjs", import.meta.url);

function startWorker() {
  const child = fork(fileURLToPath(workerFile), [], { stdio: ["ignore", "ignore", "inherit", "ipc"] });
  let done;
  const result = new Promise((resolve, reject) => { done = { resolve, reject }; });
  let readyDone;
  const ready = new Promise((resolve, reject) => {
    readyDone = { resolve, reject };
  });
  child.on("message", message => {
    if (message.ready) readyDone.resolve();
    else if (message.error) done.reject(Error(message.error));
    else done.resolve(message);
  });
  child.once("error", error => { readyDone.reject(error); done.reject(error); });
  child.once("exit", code => {
    if (code !== 0) {
      const error = Error(`Worker exited ${code}`);
      readyDone.reject(error);
      done.reject(error);
    }
  });
  return { child, ready, result };
}

export async function runFileGrantRace() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "aml-grant-race-"));
  const workers = [];
  try {
    const digest = planAction(proposal, policy).proposal_sha256;
    const grant = await createFileOneShotGrants({ directory }).issue(digest);
    workers.push(startWorker(), startWorker());
    await Promise.all(workers.map(worker => worker.ready));
    for (const worker of workers) worker.child.send({ directory, proposal, policy, grant });
    const outcomes = await Promise.all(workers.map(worker => worker.result));
    const claimMarkers = await readdir(path.join(directory, "claimed"));
    const normalized = outcomes.map(({ receipt, tool_calls }) => ({
      status: receipt.execution_status, reason: receipt.reason, tool_calls
    })).sort((a, b) => a.status.localeCompare(b.status));
    assert.deepEqual(normalized.map(x => x.status), ["blocked", "dispatched"]);
    assert.deepEqual(normalized.map(x => x.tool_calls), [0, 1]);
    assert.equal(claimMarkers.length, 1);
    return { protocol: "aml-file-grant-race-report/1", provenance: "project-authored local run",
      environment: "two Node processes sharing one local directory",
      proposal_sha256: digest, outcomes: normalized,
      total_tool_callbacks: outcomes.reduce((sum, x) => sum + x.tool_calls, 0),
      claim_markers: claimMarkers.length,
      limits: "Simulated callback only. No authenticated human approval, network filesystem, multi-machine store, or delivery proof." };
  } finally {
    for (const worker of workers) { if (worker.child.exitCode === null) worker.child.kill(); }
    await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  console.log(JSON.stringify(await runFileGrantRace(), null, 2));
}
