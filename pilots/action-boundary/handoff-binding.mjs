// Shared canonical binding for the local and file-backed handoff pilots.
import { createHash } from "node:crypto";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

export const hashHandoffBytes = bytes => createHash("sha256").update(bytes, "utf8").digest("hex");
export const validHandoffIdentity = value =>
  typeof value === "string" && !!value.trim() && value.length <= 256;

function snapshotObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("A JSON object is required");
  }
  const bytes = canonicalJSONStringify(value);
  if (Buffer.byteLength(bytes, "utf8") > 65_536) {
    throw new TypeError("Prepared request or policy is too large");
  }
  return { bytes, sha256: hashHandoffBytes(bytes) };
}

export function snapshotHandoffBinding(input) {
  const context = {};
  for (const name of ["tenant", "issuer", "actor", "audience", "tool"]) {
    const value = input?.[name];
    if (!validHandoffIdentity(value)) throw new TypeError(`Invalid ${name}`);
    context[name] = value;
  }
  const request = snapshotObject(input.preparedRequest);
  const policy = snapshotObject(input.policy);
  return { context, request, policy, sha256: hashHandoffBytes(canonicalJSONStringify({
    ...context, prepared_request_sha256: request.sha256, policy_sha256: policy.sha256
  })) };
}
