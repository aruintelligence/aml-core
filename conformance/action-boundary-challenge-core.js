import { isDeepStrictEqual } from "node:util";

export function selectChallengeCases(rows, selectedCase = null) {
  if (selectedCase !== null && !rows.some(row => row.id === selectedCase)) {
    throw new Error(`Unknown case: ${selectedCase}`);
  }
  return rows.filter(row => selectedCase === null || row.id === selectedCase);
}

export function challengeScope(selectedCase, passed) {
  return { case_scope: selectedCase === null ? "full" : "single",
    selected_case: selectedCase, full_challenge_passed: selectedCase === null && passed };
}

export function prepareCase(row, vectors) {
  const byName = new Map(vectors.cases.map(item => [item.name, item]));
  const source = byName.get(row.vector);
  if (!source) throw new Error(`Unknown vector: ${row.vector}`);
  const proposal = structuredClone(source.proposal);
  const policy = structuredClone(vectors.policy);
  if (row.policy_override_resource) {
    if (typeof row.policy_override_resource !== "string" || !policy.rules?.[0])
      throw new Error("Invalid probe policy resource");
    policy.rules[0].resource = row.policy_override_resource;
  }
  if (row.proposal_variant === "extra_top_level_field") proposal.extra = true;
  else if (row.proposal_variant) throw new Error("Unsupported proposal variant");
  if (row.policy_variant === "duplicate_matching_rule") policy.rules.push(structuredClone(policy.rules[0]));
  else if (row.policy_variant) throw new Error("Unsupported policy variant");
  const host = structuredClone(row.host);
  if (host.approval === "fixed") {
    const approved = byName.get(host.approval_digest_vector);
    if (!approved) throw new Error("Unknown approval digest vector");
    host.approval_digest_sha256 = approved.proposal_sha256;
    delete host.approval_digest_vector;
  }
  return { protocol: "aml-action-challenge-case/1", case_id: row.input_case_id || row.id, proposal, policy, host };
}

export function checkCase(row, output, invocation, vectors) {
  const byName = new Map(vectors.cases.map(item => [item.name, item]));
  const expected = row.expected;
  const expectedDigest = expected.null_digest ? null : byName.get(row.vector)?.proposal_sha256;
  const failures = [];
  if (invocation.error) failures.push(`process_error:${invocation.error.code || invocation.error.message}`);
  if (invocation.status !== 0) failures.push(`exit_code:${invocation.status}`);
  if (output?.protocol !== "aml-action-boundary-result/1") failures.push("result_protocol");
  const plan = output?.plan;
  const receipt = output?.receipt;
  if (plan?.protocol !== "aml-action-plan/1" || plan?.proposal_sha256 !== expectedDigest ||
      plan?.decision !== expected.decision || plan?.reason !== expected.reason) failures.push("plan");
  if (receipt?.protocol !== "aml-action-dispatch/1" ||
      receipt?.proposal_sha256 !== expectedDigest ||
      receipt?.policy_decision !== expected.decision ||
      receipt?.execution_status !== expected.status ||
      receipt?.reason !== expected.receipt_reason) failures.push("receipt");
  if (output?.tool_calls !== expected.tool_calls) failures.push("tool_calls");
  const dispatched = expected.executed_vector ? byName.get(expected.executed_vector)?.proposal : null;
  if (!isDeepStrictEqual(output?.executed_proposal ?? null, dispatched)) failures.push("executed_proposal");
  return failures;
}

// Human-readable field differences for an implementer's short feedback loop.
// The existing failure codes remain the stable machine-facing contract.
export function diagnoseCase(row, output, vectors) {
  const byName = new Map(vectors.cases.map(item => [item.name, item]));
  const expected = row.expected;
  const digest = expected.null_digest ? null : byName.get(row.vector)?.proposal_sha256;
  const executed = expected.executed_vector ? byName.get(expected.executed_vector)?.proposal : null;
  const fields = [
    ["protocol", "aml-action-boundary-result/1", output?.protocol],
    ["plan.protocol", "aml-action-plan/1", output?.plan?.protocol],
    ["plan.proposal_sha256", digest, output?.plan?.proposal_sha256],
    ["plan.decision", expected.decision, output?.plan?.decision],
    ["plan.reason", expected.reason, output?.plan?.reason],
    ["receipt.protocol", "aml-action-dispatch/1", output?.receipt?.protocol],
    ["receipt.proposal_sha256", digest, output?.receipt?.proposal_sha256],
    ["receipt.policy_decision", expected.decision, output?.receipt?.policy_decision],
    ["receipt.execution_status", expected.status, output?.receipt?.execution_status],
    ["receipt.reason", expected.receipt_reason, output?.receipt?.reason],
    ["tool_calls", expected.tool_calls, output?.tool_calls],
    ["executed_proposal", executed, output?.executed_proposal ?? null]
  ];
  const preview = value => {
    if (value === undefined) return "<missing>";
    const json = JSON.stringify(value);
    return json.length > 320 ? `${json.slice(0, 320)}… [truncated]` : json;
  };
  return fields.filter(([, want, got]) => !isDeepStrictEqual(want, got))
    .map(([field, want, got]) => ({ field, expected: preview(want), actual: preview(got) }));
}
