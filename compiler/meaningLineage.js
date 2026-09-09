import crypto from "node:crypto";

import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyMeaningManifestIntegrity } from "./meaningManifest.js";
import { verifySignedMeaningManifest } from "./meaningManifestAttestation.js";

const LINEAGE_PROTOCOL = "aml-meaning-lineage/1";
const ENTRY_PROTOCOL = "aml-meaning-lineage-entry/1";

function sha256Utf8(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function entryMaterial(entry) {
  return {
    protocol: ENTRY_PROTOCOL,
    version: "1.0",
    sequence: entry.sequence,
    previous_entry_sha256: entry.previous_entry_sha256,
    semantic_changed: entry.semantic_changed,
    previous_manifest_root_sha256: entry.previous_manifest_root_sha256,
    manifest_root_sha256: entry.manifest_root_sha256,
    manifest: entry.manifest,
    attestation: entry.attestation
  };
}

function hashEntry(entry) {
  return sha256Utf8(canonicalJSONStringify(entryMaterial(entry)));
}

function validateArtifact(manifest, attestation) {
  const manifestIntegrity = verifyMeaningManifestIntegrity(manifest);
  const attestationVerification = verifySignedMeaningManifest(attestation, manifest);
  return {
    verified: manifestIntegrity.verified && attestationVerification.verified,
    manifest_integrity: manifestIntegrity,
    attestation_verification: attestationVerification
  };
}

export function createMeaningLineage() {
  return {
    protocol: LINEAGE_PROTOCOL,
    version: "1.0",
    entries: []
  };
}

export function appendMeaningLineage(chain, manifest, attestation) {
  const verification = verifyMeaningLineage(chain);
  if (!verification.verified) throw new Error(`Cannot append to invalid Meaning Lineage: ${verification.reason}`);

  const artifact = validateArtifact(manifest, attestation);
  if (!artifact.verified) throw new Error("Cannot append an invalid signed Meaning Manifest artifact.");

  const previous = chain.entries.at(-1) || null;
  const entry = {
    protocol: ENTRY_PROTOCOL,
    version: "1.0",
    sequence: chain.entries.length,
    previous_entry_sha256: previous?.entry_sha256 ?? null,
    semantic_changed: previous ? previous.manifest_root_sha256 !== manifest.root_sha256 : null,
    previous_manifest_root_sha256: previous?.manifest_root_sha256 ?? null,
    manifest_root_sha256: manifest.root_sha256,
    manifest: structuredClone(manifest),
    attestation: structuredClone(attestation)
  };
  entry.entry_sha256 = hashEntry(entry);

  return {
    protocol: LINEAGE_PROTOCOL,
    version: "1.0",
    entries: [...chain.entries.map(item => structuredClone(item)), entry]
  };
}

export function verifyMeaningLineage(chain) {
  if (!chain || chain.protocol !== LINEAGE_PROTOCOL || chain.version !== "1.0" || !Array.isArray(chain.entries)) {
    return { verified: false, reason: "invalid_lineage_contract", entries_verified: 0 };
  }

  let previous = null;
  const results = [];
  for (let index = 0; index < chain.entries.length; index++) {
    const entry = chain.entries[index];
    if (!entry || entry.protocol !== ENTRY_PROTOCOL || entry.version !== "1.0" || entry.sequence !== index) {
      return { verified: false, reason: "invalid_lineage_entry_contract", failed_sequence: index, entries_verified: index, results };
    }
    if (entry.previous_entry_sha256 !== (previous?.entry_sha256 ?? null)) {
      return { verified: false, reason: "previous_entry_mismatch", failed_sequence: index, entries_verified: index, results };
    }
    if (entry.previous_manifest_root_sha256 !== (previous?.manifest_root_sha256 ?? null)) {
      return { verified: false, reason: "previous_manifest_root_mismatch", failed_sequence: index, entries_verified: index, results };
    }
    const expectedChanged = previous ? previous.manifest_root_sha256 !== entry.manifest_root_sha256 : null;
    if (entry.semantic_changed !== expectedChanged) {
      return { verified: false, reason: "semantic_change_flag_mismatch", failed_sequence: index, entries_verified: index, results };
    }
    if (entry.manifest?.root_sha256 !== entry.manifest_root_sha256 || entry.attestation?.manifest_root_sha256 !== entry.manifest_root_sha256) {
      return { verified: false, reason: "embedded_root_binding_mismatch", failed_sequence: index, entries_verified: index, results };
    }

    const artifact = validateArtifact(entry.manifest, entry.attestation);
    if (!artifact.verified) {
      return { verified: false, reason: "signed_manifest_invalid", failed_sequence: index, entries_verified: index, results };
    }
    const expectedHash = hashEntry(entry);
    if (entry.entry_sha256 !== expectedHash) {
      return { verified: false, reason: "entry_hash_mismatch", failed_sequence: index, entries_verified: index, results };
    }

    results.push({
      sequence: index,
      verified: true,
      entry_sha256: entry.entry_sha256,
      manifest_root_sha256: entry.manifest_root_sha256,
      semantic_changed: entry.semantic_changed,
      signer: artifact.attestation_verification.signer,
      signed_at: artifact.attestation_verification.signed_at
    });
    previous = entry;
  }

  return {
    verified: true,
    reason: null,
    entries_verified: chain.entries.length,
    head_entry_sha256: previous?.entry_sha256 ?? null,
    head_manifest_root_sha256: previous?.manifest_root_sha256 ?? null,
    results
  };
}
