export function createWireEnvelope({ kind, payload, version = "1.0", capabilities = [] } = {}) {
  if (!kind) throw new Error("AML wire envelope requires kind");
  return {
    protocol: "aml-wire/1",
    version,
    kind,
    capabilities: [...new Set(capabilities)].sort(),
    payload
  };
}

export function validateWireEnvelope(envelope, { allowedKinds = [] } = {}) {
  if (!envelope || envelope.protocol !== "aml-wire/1") return { valid: false, reason: "invalid_protocol" };
  if (!envelope.version || !envelope.kind) return { valid: false, reason: "missing_header" };
  if (allowedKinds.length && !allowedKinds.includes(envelope.kind)) return { valid: false, reason: "unsupported_kind" };
  return { valid: true, reason: null, kind: envelope.kind, version: envelope.version };
}

export function negotiateWireSession(local, remote, required = []) {
  const localCaps = new Set(local?.capabilities || []);
  const remoteCaps = new Set(remote?.capabilities || []);
  const common = [...localCaps].filter((cap) => remoteCaps.has(cap)).sort();
  const missing = required.filter((cap) => !common.includes(cap));
  const versions = (local?.versions || []).filter((v) => (remote?.versions || []).includes(v)).sort();
  return {
    protocol: "aml-wire-session/1",
    accepted: missing.length === 0 && versions.length > 0,
    version: versions.at(-1) || null,
    capabilities: common,
    missing_required: missing
  };
}
