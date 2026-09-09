import crypto from "node:crypto";

function hash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function leaf(key, value) {
  return hash(`${key}:${JSON.stringify(value)}`);
}

function validEntry(entry, { hidden = false } = {}) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  if (typeof entry.key !== "string" || entry.key.length === 0) return false;
  if (hidden && (typeof entry.leaf !== "string" || !/^[0-9a-f]{64}$/.test(entry.leaf))) return false;
  return true;
}

export function createDisclosureCommitment(claims = {}) {
  const entries = Object.keys(claims).sort().map((key) => ({ key, value: claims[key], leaf: leaf(key, claims[key]) }));
  const root = hash(entries.map((entry) => entry.leaf).join("|"));
  return { type: "aml-disclosure-commitment/1", root, entries };
}

export function discloseClaims(commitment, keys = []) {
  const wanted = new Set(keys);
  const disclosed = commitment.entries.filter((entry) => wanted.has(entry.key));
  const hidden = commitment.entries.filter((entry) => !wanted.has(entry.key)).map((entry) => ({ key: entry.key, leaf: entry.leaf }));
  return { type: "aml-selective-disclosure/1", root: commitment.root, disclosed, hidden };
}

export function verifyDisclosureProof(proof) {
  if (!proof || proof.type !== "aml-selective-disclosure/1") return { valid: false, reason: "invalid_type" };
  if (!Array.isArray(proof.disclosed) || !Array.isArray(proof.hidden)) return { valid: false, reason: "invalid_structure" };
  if (typeof proof.root !== "string" || !/^[0-9a-f]{64}$/.test(proof.root)) return { valid: false, reason: "invalid_root" };
  if (!proof.disclosed.every((entry) => validEntry(entry)) || !proof.hidden.every((entry) => validEntry(entry, { hidden: true }))) {
    return { valid: false, reason: "invalid_entry" };
  }

  const keys = [...proof.disclosed, ...proof.hidden].map((entry) => entry.key);
  if (new Set(keys).size !== keys.length) return { valid: false, reason: "duplicate_key" };

  try {
    const leaves = [
      ...proof.disclosed.map((entry) => ({ key: entry.key, leaf: leaf(entry.key, entry.value) })),
      ...proof.hidden.map((entry) => ({ key: entry.key, leaf: entry.leaf }))
    ].sort((a, b) => a.key.localeCompare(b.key));
    const root = hash(leaves.map((entry) => entry.leaf).join("|"));
    return { valid: root === proof.root, reason: root === proof.root ? null : "root_mismatch", root };
  } catch {
    return { valid: false, reason: "invalid_entry" };
  }
}
