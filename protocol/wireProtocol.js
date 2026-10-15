import { highestCommonProtocolVersion } from "./versionOrder.js";

const REQUIRED_ENVELOPE_FIELDS = ["protocol", "version", "kind", "capabilities", "payload"];
const OPTIONAL_ENVELOPE_FIELDS = ["session_id", "nonce", "issued_at", "expires_at"];
const ENVELOPE_FIELDS = new Set([...REQUIRED_ENVELOPE_FIELDS, ...OPTIONAL_ENVELOPE_FIELDS]);
const WIRE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-](\d{2}):(\d{2}))$/;

function wireTimestamp(value) {
  if (typeof value !== "string") return null;
  const match = WIRE_TIME.exec(value);
  if (!match) return null;
  const [, year, month, day, hour, minute, second, , , zoneHour, zoneMinute] = match;
  const y = Number(year), m = Number(month), d = Number(day);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (y < 1 || m < 1 || m > 12 || d < 1 || d > days[m - 1] || Number(hour) > 23 ||
      Number(minute) > 59 || Number(second) > 59 ||
      (zoneHour !== undefined && (Number(zoneHour) > 23 || Number(zoneMinute) > 59))) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
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
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) ||
      envelope.protocol !== "aml-wire/1") return { valid: false, reason: "invalid_protocol" };
  if (REQUIRED_ENVELOPE_FIELDS.some(field => !Object.hasOwn(envelope, field) || envelope[field] === undefined) ||
      Object.keys(envelope).some(field => !ENVELOPE_FIELDS.has(field))) {
    return { valid: false, reason: "invalid_structure" };
  }
  if (typeof envelope.version !== "string" || !envelope.version ||
      typeof envelope.kind !== "string" || !envelope.kind) return { valid: false, reason: "missing_header" };
  const caps = envelope.capabilities;
  if (!Array.isArray(caps) || caps.some(cap => typeof cap !== "string") ||
      caps.length !== new Set(caps).size) return { valid: false, reason: "invalid_capabilities" };
  if (allowedKinds.length && !allowedKinds.includes(envelope.kind)) return { valid: false, reason: "unsupported_kind" };
  for (const field of ["session_id", "nonce"]) {
    if (envelope[field] != null && typeof envelope[field] !== "string") {
      return { valid: false, reason: `invalid_${field}` };
    }
  }
  for (const field of ["issued_at", "expires_at"]) {
    if (envelope[field] != null && wireTimestamp(envelope[field]) === null) {
      return { valid: false, reason: `invalid_${field}` };
    }
  }
  if (now !== null && now !== undefined) {
    const current = wireTimestamp(now);
    if (current === null) return { valid: false, reason: "invalid_now" };
    const expiry = envelope.expires_at == null ? null : wireTimestamp(envelope.expires_at);
    if (expiry !== null && current >= expiry) return { valid: false, reason: "expired" };
  }
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
