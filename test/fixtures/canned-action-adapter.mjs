#!/usr/bin/env node
// Deliberately invalid example: look up the public case ID and copy expected
// values. It implements no policy, approval, freeze, or dispatch behavior.
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "conformance/action-boundary-challenge.json")));
const vectors = JSON.parse(fs.readFileSync(path.join(root, manifest.vectors_file)));

export function cannedAnswer(input) {
  const row = manifest.cases.find(item => item.id === input.case_id);
  if (!row) return {};
  const byName = new Map(vectors.cases.map(item => [item.name, item]));
  const expected = row.expected;
  const digest = expected.null_digest ? null : byName.get(row.vector).proposal_sha256;
  return { protocol: "aml-action-boundary-result/1",
    plan: { protocol: "aml-action-plan/1", proposal_sha256: digest,
      decision: expected.decision, reason: expected.reason },
    receipt: { protocol: "aml-action-dispatch/1", proposal_sha256: digest,
      policy_decision: expected.decision, execution_status: expected.status,
      reason: expected.receipt_reason },
    tool_calls: expected.tool_calls,
    executed_proposal: expected.executed_vector ? byName.get(expected.executed_vector).proposal : null };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  console.log(JSON.stringify(cannedAnswer(JSON.parse(fs.readFileSync(process.argv[2], "utf8")))));
}
