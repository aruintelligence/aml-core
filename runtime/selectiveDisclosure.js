import crypto from "node:crypto";

function hash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function leaf(key, value) {
  return hash(`${key}:${JSON.stringify(value)}`);
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
  const leaves = [
    ...(proof.disclosed || []).map((entry) => ({ key: entry.key, leaf: leaf(entry.key, entry.value) })),
    ...(proof.hidden || []).map((entry) => ({ key: entry.key, leaf: entry.leaf }))
  ].sort((a, b) => a.key.localeCompare(b.key));
  const root = hash(leaves.map((entry) => entry.leaf).join("|"));
  return { valid: root === proof.root, reason: root === proof.root ? null : "root_mismatch", root };
}
