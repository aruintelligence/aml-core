import { isDeepStrictEqual } from "node:util";

export function prepareCase(row, vectors) {
  const byName = new Map(vectors.cases.map(item => [item.name, item]));
  const source = byName.get(row.vector);
  if (!source) throw new Error(`Unknown vector: ${row.vector}`);
  const proposal = structuredClone(source.proposal);
  const policy = structuredClone(vectors.policy);
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
  return { protocol: "aml-action-challenge-case/1", case_id: row.id, proposal, policy, host };
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
