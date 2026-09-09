function parseOptionalTime(value) {
  if (value === null || value === undefined) return { present: false, valid: true, value: null };
  if (typeof value !== "string" || value.trim() === "") return { present: true, valid: false, value: null };
  const parsed = Date.parse(value);
  return { present: true, valid: Number.isFinite(parsed), value: Number.isFinite(parsed) ? parsed : null };
}

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
  const issued = parseOptionalTime(issued_at);
  const expires = parseOptionalTime(expires_at);
  if (!issued.valid) throw new Error("AML wire envelope requires valid issued_at");
  if (!expires.valid) throw new Error("AML wire envelope requires valid expires_at");
  if (issued.present && expires.present && expires.value <= issued.value) {
    throw new Error("AML wire envelope requires expires_at after issued_at");
  }
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

  const issued = parseOptionalTime(envelope.issued_at);
  const expires = parseOptionalTime(envelope.expires_at);
  const current = parseOptionalTime(now);
  if (!issued.valid) return { valid: false, reason: "invalid_issued_at" };
  if (!expires.valid) return { valid: false, reason: "invalid_expires_at" };
  if (!current.valid) return { valid: false, reason: "invalid_now" };
  if (issued.present && expires.present && expires.value <= issued.value) return { valid: false, reason: "invalid_time_window" };
  if (current.present && expires.present && current.value >= expires.value) return { valid: false, reason: "expired" };

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
