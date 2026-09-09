import crypto from "node:crypto";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((k) => [k, stable(value[k])]));
  return value;
}

function isPlainRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSha256Hex(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
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
  if (!isPlainRecord(bundle.files)) return { valid: false, reason: "invalid_files" };
  if (!isPlainRecord(bundle.index)) return { valid: false, reason: "invalid_index" };
  if (!isSha256Hex(bundle.root)) return { valid: false, reason: "invalid_root" };

  const fileNames = Object.keys(bundle.files).sort();
  const indexNames = Object.keys(bundle.index).sort();
  if (fileNames.length !== indexNames.length || fileNames.some((name, index) => name !== indexNames[index])) {
    return { valid: false, reason: "index_file_set_mismatch" };
  }

  try {
    for (const name of fileNames) {
      const entry = bundle.files[name];
      if (!isPlainRecord(entry)) return { valid: false, reason: "invalid_entry", entry: name };
      if (!isSha256Hex(entry.hash)) return { valid: false, reason: "invalid_entry_hash", entry: name };
      if (!isSha256Hex(bundle.index[name])) return { valid: false, reason: "invalid_index_hash", entry: name };
      if (hashContent(entry.value) !== entry.hash) return { valid: false, reason: "entry_hash_mismatch", entry: name };
      if (bundle.index[name] !== entry.hash) return { valid: false, reason: "index_mismatch", entry: name };
    }

    const expectedRoot = hashContent(bundle.index);
    if (expectedRoot !== bundle.root) return { valid: false, reason: "root_mismatch" };
    return { valid: true, reason: null, root: bundle.root };
  } catch {
    return { valid: false, reason: "invalid_content" };
  }
}
