#!/usr/bin/env node
// Project-authored fault injection against the actual reference source. These
// selected substitutions measure a finite suite's sensitivity, not safety.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dispatchAction } from "./boundary.mjs";
import { buildDispatchMatrix } from "./dispatch-matrix.mjs";

const sourceUrl = new URL("./boundary.mjs", import.meta.url);
const matrixUrl = new URL("../../docs/action-dispatch-matrix.json", import.meta.url);
const reportUrl = new URL("../../docs/action-dispatch-mutants.json", import.meta.url);
const digest = bytes => crypto.createHash("sha256").update(bytes).digest("hex");

export const mutations = Object.freeze([
  {
    id: "approval_digest_bypass",
    change: "Ignore an approval digest mismatch",
    before: "approval?.approved !== true || approval?.proposal_sha256 !== frozen.digest",
    after: "approval?.approved !== true || false"
  },
  {
    id: "one_use_claim_bypass",
    change: "Skip the host's one-use approval claim",
    before: 'plan.decision === "requires_approval" && consumeApproval !== undefined',
    after: "false && consumeApproval !== undefined"
  },
  {
    id: "post_approval_policy_bypass",
    change: "Skip policy recheck after the approval callback",
    before: "rechecked.decision !== plan.decision || rechecked.proposal_sha256 !== frozen.digest",
    after: "false"
  },
  {
    id: "post_claim_policy_bypass",
    change: "Skip policy recheck after the claim callback",
    before: "finalPlan.decision !== plan.decision || finalPlan.proposal_sha256 !== frozen.digest",
    after: "false"
  },
  {
    id: "mutable_dispatch_target",
    change: "Pass the caller's mutable object to the host callback",
    before: "executeTool(JSON.parse(frozen.bytes))",
    after: "executeTool(proposal)"
  },
  {
    id: "false_blocked_receipt",
    change: "Call an uncertain callback failure blocked",
    before: 'receipt("unknown", "host_dispatch_error")',
    after: 'receipt("blocked", "host_dispatch_error")'
  },
  {
    id: "resource_wildcard",
    change: "Accept a policy rule for another resource",
    before: "rule.resource === proposal.resource",
    after: "true"
  }
]);

function replaceExactlyOnce(source, before, after) {
  assert.equal(source.split(before).length, 2, `Expected exactly one source occurrence: ${before}`);
  return source.replace(before, after);
}

async function loadMutant(source, mutation) {
  const changed = replaceExactlyOnce(source, mutation.before, mutation.after);
  const canonicalUrl = new URL("../../protocol/canonicalJson.js", import.meta.url);
  const selfContained = replaceExactlyOnce(changed,
    'from "../../protocol/canonicalJson.js"', `from "${canonicalUrl.href}"`);
  // Each data URL is a distinct ESM module, with no temporary file or host call.
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(selfContained).toString("base64")}`;
  return (await import(moduleUrl)).dispatchAction;
}

function outcome(row) {
  return {
    proposal_resource: row.proposal_resource, policy_rule_resource: row.policy_rule_resource,
    receipt: row.receipt, approval_requests: row.approval_requests,
    claim_attempts: row.claim_attempts, claims_consumed: row.claims_consumed,
    callback_count: row.callback_count, fixture_writes: row.fixture_writes,
    callback_target: row.callback_target, caller_target_after: row.caller_target_after,
    result_target: row.result_target
  };
}

export async function resourceSubstitutionProbe(dispatch = dispatchAction) {
  const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
    resource: "outside@example.test", purpose: "Local resource substitution probe",
    arguments: { to: "outside@example.test", body: "Local marker only." } };
  const policy = { protocol: "aml-action-policy/1", rules: [
    { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: false }
  ] };
  let callbackCount = 0;
  const { receipt } = await dispatch(proposal, { policy, executeTool: async () => {
    callbackCount++;
    return { local_marker: true };
  } });
  return { execution_status: receipt.execution_status, reason: receipt.reason,
    policy_decision: receipt.policy_decision, callback_count: callbackCount };
}

export async function buildDispatchMutants() {
  const [source, matrixBytes] = await Promise.all([
    readFile(sourceUrl, "utf8"), readFile(matrixUrl, "utf8")
  ]);
  const reference = JSON.parse(matrixBytes);
  assert.deepEqual(await buildDispatchMatrix(), reference,
    "Matrix report is stale; regenerate and verify it before mutation testing");
  const baselineProbe = await resourceSubstitutionProbe();
  assert.deepEqual(baselineProbe, { execution_status: "blocked", reason: "no_exact_rule",
    policy_decision: "deny", callback_count: 0 });
  const results = [];
  for (const mutation of mutations) {
    const dispatch = await loadMutant(source, mutation);
    const rows = (await buildDispatchMatrix(dispatch)).rows;
    const differences = rows.flatMap((row, index) =>
      JSON.stringify(row) === JSON.stringify(reference.rows[index]) ? [] : [index]);
    const first = differences[0];
    const probe = await resourceSubstitutionProbe(dispatch);
    results.push({ id: mutation.id, change: mutation.change,
      matrix_changed_rows: differences.length,
      first_changed_vector: first === undefined ? null : {
        index: first, axes: Object.fromEntries(
          ["resource_scope", "policy", "approval", "claim", "callback"].map(axis => [axis, rows[first][axis]])),
        reference: outcome(reference.rows[first]), mutant: outcome(rows[first])
      },
      resource_probe_changed: JSON.stringify(probe) !== JSON.stringify(baselineProbe),
      resource_probe_result: probe });
  }
  const summary = { selected_mutants: results.length,
    matrix_detected: results.filter(row => row.matrix_changed_rows > 0).length,
    additional_probe_detected: results.filter(row => row.matrix_changed_rows === 0 && row.resource_probe_changed).length,
    undetected: results.filter(row => row.matrix_changed_rows === 0 && !row.resource_probe_changed).length };
  return { protocol: "aml-action-dispatch-mutants/1",
    provenance: "project-authored exact source substitutions and local callbacks",
    limits: "Selected mutations and finite fixtures only. No external side effect, arbitrary bug coverage, outside witness, or formal proof of production safety.",
    boundary_source_sha256: digest(source), matrix_report_sha256: digest(matrixBytes),
    matrix_vectors: reference.rows.length, resource_probe_reference: baselineProbe,
    summary, mutations: results };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (!(args.length === 0 || (args.length === 1 && ["--write", "--check"].includes(args[0])))) {
    throw new Error("Use no argument, --write, or --check");
  }
  const report = await buildDispatchMutants();
  const json = JSON.stringify(report, null, 2) + "\n";
  if (args[0] === "--write") {
    await writeFile(reportUrl, json, "utf8");
    console.log(`Wrote ${report.summary.selected_mutants} selected source mutations.`);
  } else if (args[0] === "--check") {
    assert.equal(await readFile(reportUrl, "utf8"), json,
      "Dispatch mutation report is stale; run --write");
    console.log(`${report.summary.selected_mutants} selected source mutations match the checked-in report.`);
  } else process.stdout.write(json);
}
