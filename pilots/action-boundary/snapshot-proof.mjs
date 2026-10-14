#!/usr/bin/env node
// Stateful accessors are local adversarial fixtures. No provider or person is contacted.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { dispatchAction } from "./boundary.mjs";

const reportUrl = new URL("../../docs/action-snapshot-proof.json", import.meta.url);
const sourceUrl = new URL("./boundary.mjs", import.meta.url);
const digest = value => crypto.createHash("sha256").update(value, "utf8").digest("hex");
export const modes = Object.freeze(["allow", "requires_approval"]);

export async function runSnapshotProbe(dispatch = dispatchAction) {
  const rows = [];
  for (const mode of modes) {
    let accessorReads = 0;
    const args = { to: "team@example.test" };
    Object.defineProperty(args, "body", { enumerable: true, get() {
      return ++accessorReads === 1 ? "First observed body" : "Changed on second read";
    } });
    const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
      resource: "team@example.test", purpose: "Snapshot binding fixture", arguments: args };
    const policy = { protocol: "aml-action-policy/1", rules: [
      { tool: "send_message", effect: "send", resource: "team@example.test",
        requires_approval: mode === "requires_approval" }
    ] };
    let approvalRequests = 0;
    let approvalDigest = null;
    let claimAttempts = 0;
    let callbackCount = 0;
    let callbackProposal = null;
    const { receipt } = await dispatch(proposal, { policy,
      requestApproval: async ({ proposal_sha256 }) => {
        approvalRequests++;
        approvalDigest = proposal_sha256;
        return { approved: true, proposal_sha256 };
      },
      consumeApproval: async () => { claimAttempts++; return true; },
      executeTool: async frozen => {
        callbackCount++;
        callbackProposal = frozen;
        return { local_marker: true };
      }
    });
    const callbackDigest = callbackProposal ? digest(canonicalJSONStringify(callbackProposal)) : null;
    rows.push({ mode, accessor_reads: accessorReads, approval_requests: approvalRequests,
      approval_digest: approvalDigest, claim_attempts: claimAttempts, callback_count: callbackCount,
      callback_body: callbackProposal?.arguments.body ?? null, callback_sha256: callbackDigest,
      receipt, receipt_matches_callback: receipt.proposal_sha256 === callbackDigest });
  }
  return rows;
}

export async function buildSnapshotProof() {
  return { protocol: "aml-action-snapshot-proof/1",
    provenance: "project-authored stateful accessor and local callback fixtures",
    limits: "Two local fixtures with a changing JavaScript getter. No human approval, provider effect, arbitrary object behavior, or production safety proof.",
    boundary_source_sha256: digest(await readFile(sourceUrl, "utf8")),
    rows: await runSnapshotProbe() };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (!(args.length === 0 || (args.length === 1 && ["--write", "--check"].includes(args[0])))) {
    throw new Error("Use no argument, --write, or --check");
  }
  const report = await buildSnapshotProof();
  const json = JSON.stringify(report, null, 2) + "\n";
  if (args[0] === "--write") {
    await writeFile(reportUrl, json, "utf8");
    console.log(`Wrote ${report.rows.length} local snapshot binding cases.`);
  } else if (args[0] === "--check") {
    assert.equal(await readFile(reportUrl, "utf8"), json, "Snapshot report is stale; run --write");
    console.log(`${report.rows.length} local snapshot binding cases match the checked-in report.`);
  } else process.stdout.write(json);
}
