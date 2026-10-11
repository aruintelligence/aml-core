#!/usr/bin/env node
// Reproducible project-owned rehearsal. All callbacks append to a temp file.
import assert from "node:assert/strict";
import { fork, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createFileDispatchLedger } from "./file-dispatch-ledger.mjs";

const worker = fileURLToPath(new URL("./file-dispatch-worker.mjs", import.meta.url));
const proposal = { protocol: "aml-proposed-action/1", tool: "simulated.send", effect: "send",
  resource: "mailbox:example", purpose: "dispatch ledger demo", arguments: { body: "one message", to: "example.invalid" } };
const withBody = body => ({ ...proposal, arguments: { ...proposal.arguments, body } });
const events = file => fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean) : [];

async function race(directory, eventFile) {
  const args = [directory, eventFile, "host-operation-race-001", JSON.stringify(proposal)];
  const children = [fork(worker, args, { stdio: ["ignore", "ignore", "pipe", "ipc"] }),
    fork(worker, args, { stdio: ["ignore", "ignore", "pipe", "ipc"] })];
  const results = await Promise.all(children.map(child => new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error("worker_timeout")); }, 5000);
    let ready = false;
    child.on("message", message => {
      if (message.ready) { ready = true; child.ready = true; if (children.every(item => item.ready)) children.forEach(item => item.send("go")); }
      else if (message.status || message.error) child.result = message;
    });
    child.on("error", reject);
    child.on("exit", code => {
      clearTimeout(timer);
      if (!ready || code !== 0 || !child.result?.status) reject(new Error(`worker_failed_${code}_${child.result?.error || ""}`));
      else resolve(child.result.status);
    });
  })));
  assert.equal(results.filter(x => x === "returned").length, 1);
  assert.equal(results.filter(x => ["unknown", "already_returned"].includes(x)).length, 1);
  return { status: "one_returned_one_suppressed", attempts: 2, callback_count: events(eventFile).length };
}

export async function runFileDispatchLedgerDemo() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-dispatch-ledger-"));
  const directory = path.join(temp, "private-ledger");
  const eventFile = path.join(temp, "simulated-callbacks.ndjson");
  try {
    const ledger = createFileDispatchLedger({ directory });
    const raceResult = await race(directory, eventFile);
    assert.equal(raceResult.callback_count, 1);
    const replay = await ledger.run({ operationId: "host-operation-race-001", proposal,
      executeTool: () => { throw new Error("must not run"); } });
    assert.equal(replay.status, "already_returned");
    const mismatch = await ledger.run({ operationId: "host-operation-race-001", proposal: withBody("changed message"),
      executeTool: () => { throw new Error("must not run"); } });
    assert.equal(mismatch.status, "mismatch");

    const crash = spawnSync(process.execPath, [worker, directory, eventFile,
      "host-operation-crash-001", JSON.stringify(proposal), "claim-exit"], { timeout: 5000 });
    assert.equal(crash.status, 83);
    const afterCrash = await ledger.run({ operationId: "host-operation-crash-001", proposal,
      executeTool: () => { throw new Error("must not run"); } });
    assert.equal(afterCrash.status, "unknown");
    assert.equal(afterCrash.reason, "claimed_may_have_executed");

    const afterCallbackError = await ledger.run({ operationId: "host-operation-error-001", proposal,
      executeTool: () => { fs.appendFileSync(eventFile, JSON.stringify({ operationId: "host-operation-error-001" }) + "\n");
        throw new Error("transport lost after possible side effect"); } });
    assert.equal(afterCallbackError.status, "unknown");
    const uncertainReplay = await ledger.run({ operationId: "host-operation-error-001", proposal,
      executeTool: () => { throw new Error("must not run"); } });
    assert.equal(uncertainReplay.status, "unknown");

    const legitimateSecond = await ledger.run({ operationId: "host-operation-intentional-002", proposal,
      executeTool: frozen => { fs.appendFileSync(eventFile, JSON.stringify({ operationId: "host-operation-intentional-002",
        proposal: frozen }) + "\n"); return { simulated: true }; } });
    assert.equal(legitimateSecond.status, "returned");
    assert.equal(events(eventFile).length, 3);

    return { protocol: "aml-file-dispatch-ledger-demo/1", provenance: "project-maintained local simulation",
      scenarios: [
        { id: "two-workers", title: "Two workers, one operation", ...raceResult,
          explanation: "An exclusive claim precedes the callback. Only one worker enters it." },
        { id: "replay", title: "Same ID after return", status: replay.status, callback_count: 0,
          explanation: "The returned callback is recorded; retry is suppressed, not re-executed." },
        { id: "changed-payload", title: "Same ID, changed payload", status: mismatch.status, callback_count: 0,
          explanation: "An operation ID cannot be reused with a different proposal digest." },
        { id: "crash", title: "Worker exits after claim", status: afterCrash.status, callback_count: 0,
          explanation: "The old claim survives a process exit. Outcome is unknown and no retry occurs." },
        { id: "callback-error", title: "Callback throws after possible effect", status: afterCallbackError.status,
          callback_count: 1, replay_status: uncertainReplay.status,
          explanation: "The ledger records uncertainty and suppresses a replay; a host must reconcile externally." },
        { id: "new-intent", title: "New ID, same payload", status: legitimateSecond.status, callback_count: 1,
          explanation: "A separate host intent may intentionally repeat the same payload." }
      ],
      limits: "Local trusted filesystem only. Callback counts are simulated; returned is not proof of external delivery. No automatic recovery, cross-machine guarantee, human authentication, or production authorization." };
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runFileDispatchLedgerDemo().then(report => console.log(JSON.stringify(report, null, 2))).catch(error => {
    console.error(error); process.exitCode = 1;
  });
}
