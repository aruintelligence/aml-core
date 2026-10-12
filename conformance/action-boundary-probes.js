// Seeded follow-up cases for the published action challenge. These are
// project-defined metamorphic checks, not secret tests or independent proof.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const clone = value => structuredClone(value);
const digest = value => crypto.createHash("sha256").update(canonicalJSONStringify(value)).digest("hex");

export function generateActionProbes(manifest, vectors, seed) {
  if (!/^[0-9a-f]{32}$/.test(seed)) throw new TypeError("probe_seed_must_be_32_lowercase_hex");
  if (manifest.protocol !== "aml-action-boundary-challenge/1" ||
      vectors.protocol !== "aml-action-vectors/1") throw new TypeError("unsupported_probe_contract");
  const source = new Map(vectors.cases.map(item => [item.name, item.proposal]));
  const token = seed.slice(0, 12);
  const rows = [];
  const additions = [];
  function add(id, inputCaseId, sourceName, mutate, host, expected, policyResource = null) {
    const proposal = clone(source.get(sourceName));
    if (!proposal) throw new Error(`missing_probe_source:${sourceName}`);
    mutate(proposal);
    const vector = `probe_${id.replaceAll("-", "_")}`;
    additions.push({ name: vector, proposal, proposal_sha256: digest(proposal) });
    rows.push({ id, input_case_id: inputCaseId, vector, host, expected: { ...expected,
      ...(expected.tool_calls ? { executed_vector: vector } : {}) },
      ...(policyResource ? { policy_override_resource: policyResource } : {}) });
  }
  const approved = { decision: "requires_approval", reason: "exact_rule",
    status: "dispatched", receipt_reason: "host_dispatch_returned", tool_calls: 1 };
  const denied = { decision: "deny", reason: "no_exact_rule",
    status: "blocked", receipt_reason: "no_exact_rule", tool_calls: 0 };
  const matching = { approval: "matching", tool: "return" };
  add("probe-approved-body", "approved-send", "approved_route",
    proposal => { proposal.arguments.body = `Build ${token} passed.`; }, matching, approved);
  const freshResource = `team+${token}@example.test`;
  add("probe-new-authorized-resource", "approved-send", "approved_route",
    proposal => { proposal.resource = freshResource; }, matching, approved, freshResource);
  add("probe-unapproved-resource", "changed-destination", "changed_destination",
    proposal => { proposal.resource = `outside+${token}@example.test`; }, matching, denied);
  add("probe-stale-approval", "stale-body-approval", "changed_body",
    proposal => { proposal.arguments.body = `Changed ${token} after approval.`; },
    { approval: "fixed", approval_digest_vector: "approved_route", tool: "return" },
    { decision: "requires_approval", reason: "exact_rule", status: "blocked",
      receipt_reason: "approval_missing_or_mismatched", tool_calls: 0 });
  add("probe-allowed-read-purpose", "allowed-read", "read_route",
    proposal => { proposal.purpose = `Inspect record ${token}`; },
    { approval: "missing", tool: "return" },
    { decision: "allow", reason: "exact_rule", status: "dispatched",
      receipt_reason: "host_dispatch_returned", tool_calls: 1 });
  add("probe-frozen-proposal", "mutated-while-awaiting", "approved_route",
    proposal => { proposal.arguments.body = `Original ${token}`; },
    { approval: "matching", mutate_proposal_body: `Mutation ${token}`, tool: "return" }, approved);
  return { rows, vectors: { ...vectors, cases: [...vectors.cases, ...additions] } };
}
