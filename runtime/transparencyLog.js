import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function createTransparencyLog() {
  return { type: "aml-transparency-log/1", entries: [], head: null };
}

export function appendTransparencyEntry(log, payload, { timestamp = null } = {}) {
  if (!log || log.type !== "aml-transparency-log/1") throw new Error("Invalid transparency log");
  const previous_hash = log.head;
  const body = {
    index: log.entries.length,
    previous_hash,
    payload_hash: sha256(canonicalJSONStringify(payload)),
    timestamp
  };
  const entry_hash = sha256(canonicalJSONStringify(body));
  const entry = { ...body, entry_hash };
  return {
    type: log.type,
    entries: [...log.entries, entry],
    head: entry_hash
  };
}

export function verifyTransparencyLog(log) {
  if (!log || log.type !== "aml-transparency-log/1") return { valid: false, reason: "invalid_type" };
  let previous = null;
  for (let i = 0; i < log.entries.length; i += 1) {
    const entry = log.entries[i];
    const { entry_hash, ...body } = entry;
    if (entry.index !== i) return { valid: false, reason: "index_mismatch", index: i };
    if (entry.previous_hash !== previous) return { valid: false, reason: "chain_mismatch", index: i };
    if (sha256(canonicalJSONStringify(body)) !== entry_hash) return { valid: false, reason: "hash_mismatch", index: i };
    previous = entry_hash;
  }
  if (log.head !== previous) return { valid: false, reason: "head_mismatch" };
  return { valid: true, reason: null, head: previous, size: log.entries.length };
}
