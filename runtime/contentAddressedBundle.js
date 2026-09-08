import crypto from "node:crypto";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((k) => [k, stable(value[k])]));
  return value;
}

export function hashContent(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(stable(value))).digest("hex");
}

export function createContentAddressedBundle(entries = {}) {
  const files = Object.fromEntries(Object.keys(entries).sort().map((name) => [name, { hash: hashContent(entries[name]), value: entries[name] }]));
  const index = Object.fromEntries(Object.entries(files).map(([name, entry]) => [name, entry.hash]));
  return {
    type: "aml-content-bundle/1",
    root: hashContent(index),
    index,
    files
  };
}

export function verifyContentAddressedBundle(bundle) {
  if (!bundle || bundle.type !== "aml-content-bundle/1") return { valid: false, reason: "invalid_type" };
  for (const [name, entry] of Object.entries(bundle.files || {})) {
    if (hashContent(entry.value) !== entry.hash) return { valid: false, reason: "entry_hash_mismatch", entry: name };
    if (bundle.index?.[name] !== entry.hash) return { valid: false, reason: "index_mismatch", entry: name };
  }
  const expectedRoot = hashContent(bundle.index || {});
  if (expectedRoot !== bundle.root) return { valid: false, reason: "root_mismatch" };
  return { valid: true, reason: null, root: bundle.root };
}
