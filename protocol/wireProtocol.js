import { highestCommonProtocolVersion } from "./versionOrder.js";

export function createWireEnvelope({
  kind,
  payload,
  version = "1.0",
  capabilities = [],
  session_id = null,
  nonce = null,
  issued_at = null,
  expires_at = null
} = {}) {
  if (!kind) throw new Error("AML wire envelope requires kind");
  return {
    protocol: "aml-wire/1",
    version,
    kind,
    capabilities: [...new Set(capabilities)].sort(),
    session_id,
    nonce,
    issued_at,
    expires_at,
    payload
  };
}

export function validateWireEnvelope(envelope, { allowedKinds = [], now = null } = {}) {
  if (!envelope || envelope.protocol !== "aml-wire/1") return { valid: false, reason: "invalid_protocol" };
  if (!envelope.version || !envelope.kind) return { valid: false, reason: "missing_header" };
  if (allowedKinds.length && !allowedKinds.includes(envelope.kind)) return { valid: false, reason: "unsupported_kind" };
  if (now && envelope.expires_at && new Date(now) >= new Date(envelope.expires_at)) return { valid: false, reason: "expired" };
  return { valid: true, reason: null, kind: envelope.kind, version: envelope.version };
}

export function negotiateWireSession(local, remote, required = []) {
  const localCaps = new Set(local?.capabilities || []);
  const remoteCaps = new Set(remote?.capabilities || []);
  const common = [...localCaps].filter((cap) => remoteCaps.has(cap)).sort();
  const missing = required.filter((cap) => !common.includes(cap));
  const { common: versions, selected } = highestCommonProtocolVersion(local?.versions || [], remote?.versions || []);
  return {
    protocol: "aml-wire-session/1",
    accepted: missing.length === 0 && versions.length > 0,
    version: selected,
    capabilities: common,
    missing_required: missing
  };
}
