// runtime/consentLedger.js
// ĀML — time-scoped, revocable consent ledger with hash-chained events.
// v1.1 binds the ledger header into the first event link. This is tamper evidence,
// not authentication of the claimed subject identity.

import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const PROTOCOL = "ĀML Consent Ledger";
const CURRENT_VERSION = "1.1";
const LEGACY_VERSION = "1.0";
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const ACTIONS = new Set(["grant", "revoke"]);

// Historical v1.0 serializer. Keep exact behavior for legacy verification only.
function legacyStableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(legacyStableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${legacyStableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function legacySha256(value) {
  return sha256Bytes(legacyStableStringify(value));
}

function canonicalSha256(value) {
  return sha256Bytes(canonicalJSONStringify(value));
}

function parseTimestamp(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function requireTimestamp(value, field) {
  if (value !== null && value !== undefined && parseTimestamp(value) === null) {
    throw new Error(`${field} must be a valid timestamp`);
  }
}

function headerMaterial(ledger) {
  return {
    protocol: "aml-consent-ledger-header/1",
    ledger_protocol: PROTOCOL,
    ledger_version: CURRENT_VERSION,
    subject_id: ledger.subject_id ?? null,
    created_at: ledger.created_at
  };
}

function computeHeaderHash(ledger) {
  return canonicalSha256(headerMaterial(ledger));
}

function eventCore(event) {
  return {
    sequence: event.sequence,
    timestamp: event.timestamp,
    action: event.action,
    scope: event.scope,
    expires_at: event.expires_at ?? null,
    reason: event.reason ?? null,
    previous_hash: event.previous_hash
  };
}

function validScope(scope) {
  return typeof scope === "string" && scope.trim().length > 0;
}

function validReason(reason) {
  return reason === null || reason === undefined || typeof reason === "string";
}

function validHash(value) {
  return typeof value === "string" && HASH_PATTERN.test(value);
}

export function createConsentLedger(options = {}) {
  const createdAt = options.timestamp ?? new Date().toISOString();
  requireTimestamp(createdAt, "timestamp");
  if (options.subject_id !== null && options.subject_id !== undefined && typeof options.subject_id !== "string") {
    throw new TypeError("subject_id must be a string or null");
  }
  const ledger = {
    protocol: PROTOCOL,
    version: CURRENT_VERSION,
    subject_id: options.subject_id ?? null,
    created_at: createdAt,
    header_hash: null,
    events: []
  };
  ledger.header_hash = computeHeaderHash(ledger);
  return ledger;
}

function appendEvent(ledger, event, options = {}) {
  if (!ledger || ledger.protocol !== PROTOCOL) throw new Error("Invalid ĀML consent ledger.");
  if (![CURRENT_VERSION, LEGACY_VERSION].includes(ledger.version)) throw new Error("Unsupported ĀML consent ledger version.");
  if (!Array.isArray(ledger.events)) throw new Error("Consent ledger events must be an array.");
  if (!ACTIONS.has(event.action)) throw new Error("Consent action must be grant or revoke.");
  if (!validScope(event.scope)) throw new Error("Consent scope is required.");
  if (!validReason(event.reason)) throw new TypeError("Consent reason must be a string or null.");

  const timestamp = options.timestamp ?? new Date().toISOString();
  requireTimestamp(timestamp, "timestamp");
  requireTimestamp(event.expires_at, "expires_at");

  const sequence = ledger.events.length;
  let previous_hash;
  if (sequence > 0) {
    previous_hash = ledger.events[sequence - 1].event_hash;
  } else if (ledger.version === CURRENT_VERSION) {
    const expectedHeaderHash = computeHeaderHash(ledger);
    if (ledger.header_hash !== expectedHeaderHash) throw new Error("Consent ledger header integrity failure.");
    previous_hash = expectedHeaderHash;
  } else {
    previous_hash = null;
  }

  const core = {
    sequence,
    timestamp,
    action: event.action,
    scope: event.scope,
    expires_at: event.expires_at ?? null,
    reason: event.reason ?? null,
    previous_hash
  };
  const event_hash = ledger.version === CURRENT_VERSION ? canonicalSha256(core) : legacySha256(core);
  const record = { ...core, event_hash };
  ledger.events.push(record);
  return record;
}

export function grantConsent(ledger, scope, options = {}) {
  return appendEvent(ledger, {
    action: "grant",
    scope,
    expires_at: options.expires_at ?? null,
    reason: options.reason ?? null
  }, options);
}

export function revokeConsent(ledger, scope, options = {}) {
  return appendEvent(ledger, {
    action: "revoke",
    scope,
    reason: options.reason ?? null
  }, options);
}

function failedVerification(reason, extra = {}) {
  return {
    verified: false,
    reason,
    header_bound: false,
    legacy_integrity_only: false,
    events: 0,
    head_hash: null,
    checks: [],
    ...extra
  };
}

export function verifyConsentLedger(ledger) {
  try {
    if (!ledger || typeof ledger !== "object" || Array.isArray(ledger)) {
      return failedVerification("invalid_ledger");
    }
    if (ledger.protocol !== PROTOCOL) return failedVerification("invalid_protocol");
    if (![CURRENT_VERSION, LEGACY_VERSION].includes(ledger.version)) {
      return failedVerification("unsupported_version");
    }
    if (!Array.isArray(ledger.events)) return failedVerification("invalid_events");

    const createdAtValid = parseTimestamp(ledger.created_at) !== null;
    const subjectValid = ledger.subject_id === null || ledger.subject_id === undefined || typeof ledger.subject_id === "string";
    const isCurrent = ledger.version === CURRENT_VERSION;
    const expectedHeaderHash = isCurrent && createdAtValid && subjectValid ? computeHeaderHash(ledger) : null;
    const headerHashValid = !isCurrent || (validHash(ledger.header_hash) && ledger.header_hash === expectedHeaderHash);

    let previous = isCurrent ? expectedHeaderHash : null;
    const checks = [];
    for (let index = 0; index < ledger.events.length; index += 1) {
      const event = ledger.events[index];
      if (!event || typeof event !== "object" || Array.isArray(event)) {
        checks.push({ sequence: index, structure_valid: false });
        previous = null;
        continue;
      }

      const core = eventCore(event);
      const structureValid = ACTIONS.has(event.action) && validScope(event.scope) && validReason(event.reason);
      const sequenceValid = Number.isInteger(event.sequence) && event.sequence === index;
      const previousValid = event.previous_hash === previous;
      const eventHashValid = validHash(event.event_hash);
      const timestampValid = parseTimestamp(event.timestamp) !== null;
      const expiresAtValid = event.expires_at === null || event.expires_at === undefined || parseTimestamp(event.expires_at) !== null;
      let expectedHash = null;
      let hashValid = false;
      try {
        expectedHash = isCurrent ? canonicalSha256(core) : legacySha256(core);
        hashValid = eventHashValid && event.event_hash === expectedHash;
      } catch {
        hashValid = false;
      }

      checks.push({
        sequence: index,
        structure_valid: structureValid,
        action_valid: ACTIONS.has(event.action),
        scope_valid: validScope(event.scope),
        sequence_valid: sequenceValid,
        previous_hash_valid: previousValid,
        hash_valid: hashValid,
        timestamp_valid: timestampValid,
        expires_at_valid: expiresAtValid
      });
      previous = eventHashValid ? event.event_hash : null;
    }

    const eventsValid = checks.every(check =>
      check.structure_valid &&
      check.sequence_valid &&
      check.previous_hash_valid &&
      check.hash_valid &&
      check.timestamp_valid &&
      check.expires_at_valid
    );
    const verified = createdAtValid && subjectValid && headerHashValid && eventsValid;

    return {
      verified,
      reason: verified ? null : "consent_ledger_verification_failed",
      version: ledger.version,
      created_at_valid: createdAtValid,
      subject_id_valid: subjectValid,
      header_hash_valid: headerHashValid,
      header_bound: isCurrent && headerHashValid,
      legacy_integrity_only: ledger.version === LEGACY_VERSION && verified,
      events: checks.length,
      head_hash: ledger.events.at(-1)?.event_hash || (isCurrent && headerHashValid ? ledger.header_hash : null),
      checks
    };
  } catch {
    return failedVerification("verification_error");
  }
}

export function resolveConsent(ledger, scope, options = {}) {
  if (!validScope(scope)) return { granted: false, reason: "invalid consent scope", scope };
  const integrity = verifyConsentLedger(ledger);
  if (!integrity.verified) return { granted: false, reason: "consent ledger integrity failure", scope };

  const evaluationTime = options.at ?? new Date().toISOString();
  const now = parseTimestamp(evaluationTime);
  if (now === null) return { granted: false, reason: "invalid evaluation timestamp", scope };

  const relevant = ledger.events.filter(event => event.scope === scope);
  const latest = relevant.at(-1);
  if (!latest) return { granted: false, reason: "no consent event for scope", scope };
  if (latest.action === "revoke") return { granted: false, reason: "consent revoked", scope, event: latest };
  if (latest.action !== "grant") return { granted: false, reason: "invalid consent action", scope, event: latest };
  if (latest.expires_at) {
    const expiresAt = parseTimestamp(latest.expires_at);
    if (expiresAt === null) return { granted: false, reason: "invalid consent expiry", scope, event: latest };
    if (expiresAt <= now) return { granted: false, reason: "consent expired", scope, event: latest };
  }
  return { granted: true, reason: "active consent grant", scope, event: latest };
}

export function consentContext(ledger, mappings = {}, options = {}) {
  const context = {};
  for (const [contextKey, scope] of Object.entries(mappings)) {
    context[contextKey] = resolveConsent(ledger, scope, options).granted;
  }
  return context;
}
