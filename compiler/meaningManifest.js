import crypto from "node:crypto";

import { meaningFingerprint } from "./meaningFingerprint.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const MANIFEST_PROTOCOL = "aml-meaning-manifest/1";
const MATERIAL_PROTOCOL = "aml-meaning-manifest-material/1";
const FINGERPRINT_PROTOCOL = "aml-meaning-fingerprint/1";

function sha256Utf8(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function assertManifestPath(value) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError("Meaning Manifest path must be a non-empty string.");
  if (value.includes("\\") || value.includes("\0") || value.startsWith("/") || /^[A-Za-z]:\//.test(value)) {
    throw new Error(`Meaning Manifest path must be a portable relative POSIX path: ${value}`);
  }
  const segments = value.split("/");
  if (segments.some(segment => !segment || segment === "." || segment === "..")) {
    throw new Error(`Meaning Manifest path may not contain empty, dot, or parent segments: ${value}`);
  }
  return value;
}

function normalizeSources(sources) {
  let entries;
  if (Array.isArray(sources)) {
    entries = sources.map(entry => {
      if (!entry || typeof entry !== "object") throw new TypeError("Meaning Manifest source entry must be an object.");
      return [entry.path, entry.source];
    });
  } else if (sources && typeof sources === "object") {
    entries = Object.entries(sources);
  } else {
    throw new TypeError("Meaning Manifest sources must be a path-to-source object or entry array.");
  }

  const seen = new Set();
  return entries.map(([rawPath, source]) => {
    const path = assertManifestPath(rawPath);
    if (seen.has(path)) throw new Error(`Duplicate Meaning Manifest path: ${path}`);
    seen.add(path);
    if (typeof source !== "string") throw new TypeError(`Meaning Manifest source must be a string: ${path}`);
    return { path, source };
  }).sort((a, b) => a.path.localeCompare(b.path));
}

function manifestMaterial(files) {
  return {
    protocol: MATERIAL_PROTOCOL,
    fingerprint_protocol: FINGERPRINT_PROTOCOL,
    files: files.map(file => ({
      path: file.path,
      fingerprint: file.fingerprint,
      amt_version: file.amt_version
    }))
  };
}

function rootFor(files) {
  return sha256Utf8(canonicalJSONStringify(manifestMaterial(files)));
}

export function createMeaningManifest(sources, options = {}) {
  const entries = normalizeSources(sources);
  if (entries.length === 0) throw new Error("Meaning Manifest requires at least one AML source.");

  const files = entries.map(entry => {
    const record = meaningFingerprint(entry.source, options);
    return {
      path: entry.path,
      fingerprint: record.fingerprint,
      amt_version: record.amt_version
    };
  });

  return {
    protocol: MANIFEST_PROTOCOL,
    version: "1.0",
    algorithm: "sha256",
    material_protocol: MATERIAL_PROTOCOL,
    fingerprint_protocol: FINGERPRINT_PROTOCOL,
    file_count: files.length,
    files,
    root_sha256: rootFor(files)
  };
}

export function verifyMeaningManifest(manifest, sources, options = {}) {
  try {
    if (!manifest || manifest.protocol !== MANIFEST_PROTOCOL || manifest.version !== "1.0") {
      return { verified: false, reason: "invalid_manifest_protocol" };
    }
    if (manifest.algorithm !== "sha256" || manifest.material_protocol !== MATERIAL_PROTOCOL || manifest.fingerprint_protocol !== FINGERPRINT_PROTOCOL) {
      return { verified: false, reason: "unsupported_manifest_contract" };
    }
    if (!Array.isArray(manifest.files) || manifest.files.length === 0 || manifest.file_count !== manifest.files.length) {
      return { verified: false, reason: "invalid_manifest_files" };
    }
    if (typeof manifest.root_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(manifest.root_sha256)) {
      return { verified: false, reason: "invalid_manifest_root" };
    }

    const manifestPaths = new Set();
    let previousPath = null;
    for (const file of manifest.files) {
      const path = assertManifestPath(file?.path);
      if (manifestPaths.has(path)) return { verified: false, reason: "duplicate_manifest_path", path };
      manifestPaths.add(path);
      if (previousPath !== null && previousPath.localeCompare(path) >= 0) {
        return { verified: false, reason: "manifest_paths_not_sorted", path };
      }
      previousPath = path;
      if (typeof file.fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(file.fingerprint)) {
        return { verified: false, reason: "invalid_file_fingerprint", path };
      }
    }

    const normalized = normalizeSources(sources);
    const sourcePaths = new Set(normalized.map(entry => entry.path));
    if (sourcePaths.size !== manifestPaths.size || [...manifestPaths].some(path => !sourcePaths.has(path))) {
      return { verified: false, reason: "source_set_mismatch" };
    }

    const sourceByPath = new Map(normalized.map(entry => [entry.path, entry.source]));
    const recomputedFiles = manifest.files.map(file => {
      const record = meaningFingerprint(sourceByPath.get(file.path), options);
      return { path: file.path, fingerprint: record.fingerprint, amt_version: record.amt_version };
    });

    const mismatches = manifest.files
      .map((file, index) => ({
        path: file.path,
        expected: file.fingerprint,
        observed: recomputedFiles[index].fingerprint
      }))
      .filter(item => item.expected !== item.observed);

    const expectedRoot = rootFor(manifest.files);
    const observedRoot = rootFor(recomputedFiles);
    const declaredRootValid = expectedRoot === manifest.root_sha256;
    const sourceRootValid = observedRoot === manifest.root_sha256;
    const verified = declaredRootValid && sourceRootValid && mismatches.length === 0;

    return {
      verified,
      reason: verified ? null : mismatches.length ? "file_fingerprint_mismatch" : !declaredRootValid ? "manifest_root_mismatch" : "source_root_mismatch",
      file_count: manifest.files.length,
      mismatches,
      declared_root_valid: declaredRootValid,
      source_root_valid: sourceRootValid,
      expected_root_sha256: expectedRoot,
      observed_root_sha256: observedRoot
    };
  } catch (error) {
    return { verified: false, reason: error instanceof Error ? error.message : "meaning_manifest_verification_error" };
  }
}
