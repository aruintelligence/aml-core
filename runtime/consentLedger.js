// runtime/consentLedger.js
// ĀML v1.3 — time-scoped, revocable consent ledger with hash-chained events.

import crypto from "node:crypto";

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

export function createConsentLedger(options = {}) {
  return {
    protocol: "ĀML Consent Ledger",
    version: "1.0",
    subject_id: options.subject_id || null,
    created_at: options.timestamp ?? new Date().toISOString(),
    events: []
  };
}

function appendEvent(ledger, event, options = {}) {
  if (!ledger || ledger.protocol !== "ĀML Consent Ledger") throw new Error("Invalid ĀML consent ledger.");
  const sequence = ledger.events.length;
  const previous_hash = sequence === 0 ? null : ledger.events[sequence - 1].event_hash;
  const core = {
    sequence,
    timestamp: options.timestamp ?? new Date().toISOString(),
    action: event.action,
    scope: event.scope,
    expires_at: event.expires_at ?? null,
    reason: event.reason ?? null,
    previous_hash
  };
  const record = { ...core, event_hash: sha256(core) };
  ledger.events.push(record);
  return record;
}

export function grantConsent(ledger, scope, options = {}) {
  if (!scope || typeof scope !== "string") throw new Error("Consent scope is required.");
  return appendEvent(ledger, { action: "grant", scope, expires_at: options.expires_at ?? null, reason: options.reason ?? null }, options);
}

export function revokeConsent(ledger, scope, options = {}) {
  if (!scope || typeof scope !== "string") throw new Error("Consent scope is required.");
  return appendEvent(ledger, { action: "revoke", scope, reason: options.reason ?? null }, options);
}

export function verifyConsentLedger(ledger) {
  if (!ledger || ledger.protocol !== "ĀML Consent Ledger") throw new Error("Invalid ĀML consent ledger.");
  let previous = null;
  const checks = ledger.events.map((event, index) => {
    const core = {
      sequence: event.sequence,
      timestamp: event.timestamp,
      action: event.action,
      scope: event.scope,
      expires_at: event.expires_at ?? null,
      reason: event.reason ?? null,
      previous_hash: event.previous_hash
    };
    const sequenceValid = event.sequence === index;
    const previousValid = event.previous_hash === previous;
    const hashValid = event.event_hash === sha256(core);
    previous = event.event_hash;
    return { sequence: index, sequence_valid: sequenceValid, previous_hash_valid: previousValid, hash_valid: hashValid };
  });
  return {
    verified: checks.every(check => check.sequence_valid && check.previous_hash_valid && check.hash_valid),
    events: checks.length,
    head_hash: ledger.events.at(-1)?.event_hash || null,
    checks
  };
}

export function resolveConsent(ledger, scope, options = {}) {
  const integrity = verifyConsentLedger(ledger);
  if (!integrity.verified) return { granted: false, reason: "consent ledger integrity failure", scope };
  const now = new Date(options.at ?? new Date().toISOString()).getTime();
  const relevant = ledger.events.filter(event => event.scope === scope);
  const latest = relevant.at(-1);
  if (!latest) return { granted: false, reason: "no consent event for scope", scope };
  if (latest.action === "revoke") return { granted: false, reason: "consent revoked", scope, event: latest };
  if (latest.expires_at && new Date(latest.expires_at).getTime() <= now) {
    return { granted: false, reason: "consent expired", scope, event: latest };
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
