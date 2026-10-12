#!/usr/bin/env node
// Actual separate-process gate invocations. No network or external tool.
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const workerFile = fileURLToPath(new URL("./a2ui-file-claim-worker.mjs", import.meta.url));

function worker() {
  const child = fork(workerFile, [], { stdio: ["ignore", "ignore", "inherit", "ipc"] });
  let timeout;
  let settled = false;
  let readyResolve;
  let readyReject;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const result = new Promise((resolve, reject) => {
    timeout = setTimeout(() => reject(Error("worker_timeout")), 10_000);
    child.on("message", data => {
      if (data.ready) { readyResolve(); return; }
      settled = true;
      clearTimeout(timeout);
      if (data.error) reject(Error(data.error)); else resolve(data);
    });
    child.once("error", error => { clearTimeout(timeout); readyReject(error); reject(error); });
    child.once("exit", code => {
      if (!settled) { clearTimeout(timeout); const error = Error(`worker_exit_${code}`);
        readyReject(error); reject(error); }
    });
  });
  return { child, ready, result };
}

async function run(mode, spec) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "aml-a2ui-claims-"));
  const children = [];
  try {
    const send = async (input, child) => {
      await child.ready;
      child.child.send({ mode, directory, ...input });
      return child.result;
    };
    let results;
    if (spec.sequential) {
      const first = worker(); children.push(first);
      results = [await send(spec.attempts[0], first)];
      const second = worker(); children.push(second);
      results.push(await send(spec.attempts[1], second));
    } else {
      const pair = spec.attempts.map(() => worker()); children.push(...pair);
      await Promise.all(pair.map(x => x.ready));
      results = await Promise.all(spec.attempts.map((input, i) => send(input, pair[i])));
    }
    const markers = (await readdir(directory)).filter(name => name.endsWith(".claim"));
    const summary = { tool_callbacks: results.reduce((sum, x) => sum + x.tool_calls, 0),
      claimed: results.filter(x => x.invocation === "claimed").length,
      reused: results.filter(x => x.invocation === "reused").length,
      claim_markers: markers.length,
      response_codes: results.map(x => x.response_code || "value").sort(),
      receipt_statuses: results.map(x => x.receipt_status || "none").sort() };
    return summary;
  } finally {
    for (const entry of children) if (entry.child.exitCode === null) entry.child.kill();
    await rm(directory, { recursive: true, force: true });
  }
}

export async function runA2UIFileClaimRace() {
  const common = { functionCallId: "call_1", sessionId: "host-session-A", body: "Original" };
  const specs = [
    { id: "two_workers", title: "Two workers, one ID", attempts: [common, common],
      expected: [2, 1], markers: 1 },
    { id: "changed_body", title: "Same ID, changed body", attempts: [common,
      { ...common, body: "Changed" }], expected: [2, 1], markers: 1 },
    { id: "after_restart", title: "New worker, old ID", attempts: [common, common],
      sequential: true, expected: [2, 1], markers: 1 },
    { id: "separate_sessions", title: "Two trusted sessions", attempts: [common,
      { ...common, sessionId: "host-session-B" }], expected: [2, 2], markers: 2 }
  ];
  const cases = [];
  for (const spec of specs) {
    const before = await run("local", spec);
    const after = await run("file", spec);
    assert.equal(before.tool_callbacks, spec.expected[0], `${spec.id}:local`);
    assert.equal(after.tool_callbacks, spec.expected[1], `${spec.id}:file`);
    assert.equal(after.claim_markers, spec.markers, spec.id);
    assert.equal(after.reused, 2 - spec.expected[1], spec.id);
    assert.deepEqual(after.response_codes,
      spec.expected[1] === 1 ? ["INVALID_FUNCTION_CALL", "value"] : ["value", "value"]);
    cases.push({ id: spec.id, title: spec.title,
      scheduling: spec.sequential ? "sequential new OS process" : "parallel OS processes",
      before, after });
  }
  return { protocol: "aml-a2ui-file-claim-race/1",
    provenance: "project-authored two-process local execution",
    cases,
    limits: "Simulated callback and approval. Local private filesystem only; not multi-machine coordination, authenticated user consent, or proof of delivery." };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  console.log(JSON.stringify(await runA2UIFileClaimRace(), null, 2));
}
