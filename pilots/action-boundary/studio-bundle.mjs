// A portable calculation record. Verification recomputes its contents; it does
// not authenticate the author, the policy owner, or a real approval.
import { planAction } from "./boundary.mjs";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

export const STUDIO_PROTOCOL = "aml-action-studio-bundle/1";
export const STUDIO_SOURCE = "project-authored local browser preview";
export const STUDIO_LIMITS = "Calculation consistency only. No trusted policy, identity, approval, live tool, or delivery proof.";
const planFields = ["protocol", "proposal_sha256", "decision", "reason"];
const sameKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join("|") === [...keys].sort().join("|");

export function makeStudioBundle(proposal, policy) {
  const plan = planAction(proposal, policy);
  return { protocol: STUDIO_PROTOCOL, source: STUDIO_SOURCE, proposal, policy, plan,
    canonical_proposal_json: plan.proposal_sha256 === null ? null : canonicalJSONStringify(proposal),
    limits: STUDIO_LIMITS };
}

export function verifyStudioBundle(bundle) {
  const failures = [];
  if (!sameKeys(bundle, ["protocol", "source", "proposal", "policy", "plan", "canonical_proposal_json", "limits"]) ||
      bundle.protocol !== STUDIO_PROTOCOL || bundle.source !== STUDIO_SOURCE || bundle.limits !== STUDIO_LIMITS) {
    failures.push("invalid_bundle_shape");
  }
  if (!sameKeys(bundle?.plan, planFields)) failures.push("invalid_plan_shape");
  if (failures.length) return { protocol: "aml-action-studio-verification/1", consistent: false, failures };

  let expected;
  try { expected = makeStudioBundle(bundle.proposal, bundle.policy); }
  catch { failures.push("recomputation_failed"); }
  if (expected) {
    for (const field of planFields) {
      if (bundle.plan[field] !== expected.plan[field]) failures.push(`plan.${field}_mismatch`);
    }
    if (bundle.canonical_proposal_json !== expected.canonical_proposal_json) {
      failures.push("canonical_proposal_json_mismatch");
    }
  }
  return { protocol: "aml-action-studio-verification/1", consistent: failures.length === 0,
    failures, interpretation: "Recomputed against the policy supplied in this bundle; no external authority checked." };
}
