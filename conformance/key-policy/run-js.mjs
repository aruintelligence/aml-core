// JS reference decisions for conformance/key-policy/vectors.json.
import { verifyCapabilityToken } from "../../runtime/capabilityToken.js";
import { verifyThresholdAuthorization } from "../../runtime/thresholdAuthorization.js";

export function decide(kind, artifact) {
  if (kind === "capability-token") {
    const r = verifyCapabilityToken(artifact);
    return { valid: r.valid === true, reason: r.reason ?? null };
  }
  if (kind === "threshold-authorization") {
    const r = verifyThresholdAuthorization(artifact);
    return { valid: r.valid === true, reason: r.reason ?? null, valid_signatures: r.valid_signatures,
      rejected_key_types: r.rejected_key_types ?? [] };
  }
  throw new Error(`unknown vector kind ${kind}`);
}

export function runVectors(vectors) {
  return { implementation: "javascript", results: vectors.cases.map(c => ({ name: c.name, decision: decide(c.kind, c.artifact) })) };
}
