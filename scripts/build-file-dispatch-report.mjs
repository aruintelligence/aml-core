#!/usr/bin/env node
// Regenerate the real two-process demo and compare its normalized six-scenario report.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runFileDispatchLedgerDemo } from "../pilots/action-boundary/file-dispatch-ledger-demo.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const report = await runFileDispatchLedgerDemo();
if (process.argv.includes("--check")) {
  const published = JSON.parse(fs.readFileSync(path.join(root, "docs/file-dispatch-report.json"), "utf8"));
  assert.deepEqual(published, report);
  assert.deepEqual(report.scenarios.map(row => row.callback_count), [1, 0, 0, 0, 1, 1]);
  console.log("Verified six dispatch-ledger scenarios, a real two-process race, and a process-exit claim");
} else {
  console.log(JSON.stringify(report, null, 2));
}
