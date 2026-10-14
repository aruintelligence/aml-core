#!/usr/bin/env node
// Exhaustive over three binary rule-binding axes only. The callback is local.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dispatchAction } from "./boundary.mjs";

const reportUrl = new URL("../../docs/action-policy-tuple.json", import.meta.url);
export const tupleAxes = Object.freeze({
  tool: ["exact", "other"], effect: ["exact", "other"], resource: ["exact", "other"]
});

export async function buildPolicyTuple(dispatch = dispatchAction) {
  const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
    resource: "team@example.test", purpose: "Local policy tuple fixture",
    arguments: { to: "team@example.test", body: "Tuple fixture only." } };
  const rows = [];
  for (const tool of tupleAxes.tool) for (const effect of tupleAxes.effect) for (const resource of tupleAxes.resource) {
    const rule = {
      tool: tool === "exact" ? proposal.tool : "archive_message",
      effect: effect === "exact" ? proposal.effect : "write",
      resource: resource === "exact" ? proposal.resource : "outside@example.test",
      requires_approval: false
    };
    let callbackCount = 0;
    let callbackTarget = null;
    const { receipt } = await dispatch(proposal, {
      policy: { protocol: "aml-action-policy/1", rules: [rule] },
      executeTool: async frozen => {
        callbackCount++;
        callbackTarget = frozen.arguments.to;
        return { local_marker: true };
      }
    });
    rows.push({ match: { tool, effect, resource },
      proposal: { tool: proposal.tool, effect: proposal.effect, resource: proposal.resource },
      rule: { tool: rule.tool, effect: rule.effect, resource: rule.resource },
      receipt, callback_count: callbackCount, callback_target: callbackTarget });
  }
  return { protocol: "aml-action-policy-tuple/1",
    provenance: "project-authored local eight-case rule-binding cross-product",
    limits: "Eight binary combinations of one valid allow rule and one local returning callback. No approval, provider call, delivery, arbitrary policy set, or production safety proof.",
    axes: tupleAxes, rows };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (!(args.length === 0 || (args.length === 1 && ["--write", "--check"].includes(args[0])))) {
    throw new Error("Use no argument, --write, or --check");
  }
  const report = await buildPolicyTuple();
  const json = JSON.stringify(report, null, 2) + "\n";
  if (args[0] === "--write") {
    await writeFile(reportUrl, json, "utf8");
    console.log(`Wrote ${report.rows.length} local policy tuple cases.`);
  } else if (args[0] === "--check") {
    assert.equal(await readFile(reportUrl, "utf8"), json, "Policy tuple is stale; run --write");
    console.log(`${report.rows.length} local policy tuple cases match the checked-in report.`);
  } else process.stdout.write(json);
}
