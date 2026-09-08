// runtime/auditStream.js
// ĀML v1.3 — append-only SHA-256 hash-chained runtime audit streams.

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

export function createAuditStream(options = {}) {
  return {
    protocol: "ĀML Runtime Audit Stream",
    version: "1.0",
    stream_id: options.stream_id || crypto.randomUUID(),
    created_at: options.timestamp ?? new Date().toISOString(),
    entries: []
  };
}

export function appendAuditEvent(stream, event, options = {}) {
  if (!stream || stream.protocol !== "ĀML Runtime Audit Stream") throw new Error("Invalid ĀML runtime audit stream.");
  const sequence = stream.entries.length;
  const previous_hash = sequence === 0 ? null : stream.entries[sequence - 1].entry_hash;
  const entryCore = {
    sequence,
    timestamp: options.timestamp ?? new Date().toISOString(),
    event_type: event.event_type || "runtime_event",
    payload: structuredClone(event.payload ?? event),
    previous_hash
  };
  const entry_hash = sha256(entryCore);
  const entry = { ...entryCore, entry_hash };
  stream.entries.push(entry);
  return entry;
}

export function verifyAuditStream(stream) {
  if (!stream || stream.protocol !== "ĀML Runtime Audit Stream") throw new Error("Invalid ĀML runtime audit stream.");
  const checks = [];
  let previous = null;
  for (let i = 0; i < stream.entries.length; i++) {
    const entry = stream.entries[i];
    const core = {
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      event_type: entry.event_type,
      payload: entry.payload,
      previous_hash: entry.previous_hash
    };
    const expectedHash = sha256(core);
    const sequenceValid = entry.sequence === i;
    const previousValid = entry.previous_hash === previous;
    const hashValid = entry.entry_hash === expectedHash;
    checks.push({ sequence: i, sequence_valid: sequenceValid, previous_hash_valid: previousValid, hash_valid: hashValid });
    previous = entry.entry_hash;
  }
  return {
    verified: checks.every(item => item.sequence_valid && item.previous_hash_valid && item.hash_valid),
    entries: checks.length,
    checks,
    head_hash: stream.entries.at(-1)?.entry_hash || null
  };
}
