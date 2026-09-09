import crypto from "node:crypto";

import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { meaningFingerprint } from "./meaningFingerprint.js";
import { semanticDiff } from "./semanticDiff.js";
import { verifyMeaningManifestIntegrity } from "./meaningManifest.js";
import { verifySignedMeaningManifest } from "./meaningManifestAttestation.js";
import { verifyMeaningLineage } from "./meaningLineage.js";

const PROTOCOL = "aml-semantic-release-proof/1";
const VERSION = "1.0";
const ALGORITHM = "Ed25519";
const MATERIAL_PROTOCOL = "aml-semantic-release-proof-material/1";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function validHash(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function validTimestamp(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(Date.parse(value));
}

function publicKeyFingerprint(publicKey) {
  return sha256(publicKey.export({ type: "spki", format: "der" }));
}

function manifestMap(manifest) {
  return new Map((manifest?.files || []).map(file => [file.path, file]));
}

function comparePaths(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sameCanonical(a, b) {
  return canonicalJSONStringify(a) === canonicalJSONStringify(b);
}

function proofMaterial(proof) {
  return {
    protocol: MATERIAL_PROTOCOL,
    proof_protocol: PROTOCOL,
    proof_version: VERSION,
    algorithm: ALGORITHM,
    release_id: proof.release_id,
    previous_release_id: proof.previous_release_id,
    generated_at: proof.generated_at,
    signer: proof.signer ?? null,
    public_key_sha256: proof.public_key_sha256,
    before_manifest: proof.before_manifest,
    before_attestation: proof.before_attestation,
    after_manifest: proof.after_manifest,
    after_attestation: proof.after_attestation,
    lineage: proof.lineage,
    lineage_head_sha256: proof.lineage_head_sha256,
    before_manifest_root_sha256: proof.before_manifest_root_sha256,
    after_manifest_root_sha256: proof.after_manifest_root_sha256,
    semantic_changed: proof.semantic_changed,
    change_summary: proof.change_summary,
    changes: proof.changes
  };
}

function buildChanges(beforeManifest, afterManifest, beforeSources, afterSources) {
  const before = manifestMap(beforeManifest);
  const after = manifestMap(afterManifest);
  const paths = [...new Set([...before.keys(), ...after.keys()])].sort(comparePaths);
  const changes = [];

  for (const path of paths) {
    const left = before.get(path) || null;
    const right = after.get(path) || null;
    if (!left) {
      const source = afterSources?.[path];
      if (typeof source !== "string") throw new Error(`Missing after source for added file: ${path}`);
      const observed = meaningFingerprint(source);
      if (observed.fingerprint !== right.fingerprint || observed.amt_version !== right.amt_version) {
        throw new Error(`Added source does not match after Meaning Manifest: ${path}`);
      }
      changes.push({ path, kind: "added", before_fingerprint: null, after_fingerprint: right.fingerprint, after_source: source });
      continue;
    }
    if (!right) {
      const source = beforeSources?.[path];
      if (typeof source !== "string") throw new Error(`Missing before source for removed file: ${path}`);
      const observed = meaningFingerprint(source);
      if (observed.fingerprint !== left.fingerprint || observed.amt_version !== left.amt_version) {
        throw new Error(`Removed source does not match before Meaning Manifest: ${path}`);
      }
      changes.push({ path, kind: "removed", before_fingerprint: left.fingerprint, after_fingerprint: null, before_source: source });
      continue;
    }
    if (left.fingerprint === right.fingerprint && left.amt_version === right.amt_version) {
      changes.push({ path, kind: "unchanged", before_fingerprint: left.fingerprint, after_fingerprint: right.fingerprint });
      continue;
    }

    const beforeSource = beforeSources?.[path];
    const afterSource = afterSources?.[path];
    if (typeof beforeSource !== "string" || typeof afterSource !== "string") {
      throw new Error(`Missing source snapshots for changed file: ${path}`);
    }
    const leftObserved = meaningFingerprint(beforeSource);
    const rightObserved = meaningFingerprint(afterSource);
    if (leftObserved.fingerprint !== left.fingerprint || leftObserved.amt_version !== left.amt_version) {
      throw new Error(`Changed before source does not match before Meaning Manifest: ${path}`);
    }
    if (rightObserved.fingerprint !== right.fingerprint || rightObserved.amt_version !== right.amt_version) {
      throw new Error(`Changed after source does not match after Meaning Manifest: ${path}`);
    }
    changes.push({
      path,
      kind: "changed",
      before_fingerprint: left.fingerprint,
      after_fingerprint: right.fingerprint,
      before_source: beforeSource,
      after_source: afterSource,
      semantic_diff: semanticDiff(beforeSource, afterSource)
    });
  }

  return changes;
}

function summarize(changes) {
  const summary = { added: 0, removed: 0, changed: 0, unchanged: 0 };
  for (const change of changes) summary[change.kind] += 1;
  return summary;
}

function verifyNestedArtifacts(proof) {
  const beforeIntegrity = verifyMeaningManifestIntegrity(proof.before_manifest);
  const afterIntegrity = verifyMeaningManifestIntegrity(proof.after_manifest);
  const beforeAttestation = verifySignedMeaningManifest(proof.before_attestation, proof.before_manifest);
  const afterAttestation = verifySignedMeaningManifest(proof.after_attestation, proof.after_manifest);
  const lineage = verifyMeaningLineage(proof.lineage);
  return { beforeIntegrity, afterIntegrity, beforeAttestation, afterAttestation, lineage };
}

function verifyLineageAdjacency(proof, lineageVerification) {
  if (!lineageVerification.verified || !Array.isArray(proof.lineage?.entries) || proof.lineage.entries.length < 2) return false;
  const afterEntry = proof.lineage.entries.at(-1);
  const beforeEntry = proof.lineage.entries.at(-2);
  return (
    afterEntry.entry_sha256 === proof.lineage_head_sha256 &&
    beforeEntry.manifest_root_sha256 === proof.before_manifest.root_sha256 &&
    afterEntry.manifest_root_sha256 === proof.after_manifest.root_sha256 &&
    sameCanonical(beforeEntry.manifest, proof.before_manifest) &&
    sameCanonical(beforeEntry.attestation, proof.before_attestation) &&
    sameCanonical(afterEntry.manifest, proof.after_manifest) &&
    sameCanonical(afterEntry.attestation, proof.after_attestation)
  );
}

function verifyChanges(proof) {
  try {
    if (!Array.isArray(proof.changes)) return { valid: false, reason: "invalid_changes" };
    const before = manifestMap(proof.before_manifest);
    const after = manifestMap(proof.after_manifest);
    const expectedPaths = [...new Set([...before.keys(), ...after.keys()])].sort(comparePaths);
    if (proof.changes.length !== expectedPaths.length) return { valid: false, reason: "change_set_size_mismatch" };

    for (let index = 0; index < expectedPaths.length; index++) {
      const path = expectedPaths[index];
      const change = proof.changes[index];
      if (!change || change.path !== path) return { valid: false, reason: "change_path_mismatch", path };
      const left = before.get(path) || null;
      const right = after.get(path) || null;
      const expectedKind = !left ? "added" : !right ? "removed" : left.fingerprint === right.fingerprint && left.amt_version === right.amt_version ? "unchanged" : "changed";
      if (change.kind !== expectedKind) return { valid: false, reason: "change_kind_mismatch", path };
      if (change.before_fingerprint !== (left?.fingerprint ?? null) || change.after_fingerprint !== (right?.fingerprint ?? null)) {
        return { valid: false, reason: "change_fingerprint_binding_mismatch", path };
      }

      if (expectedKind === "added") {
        if (typeof change.after_source !== "string" || change.before_source !== undefined || change.semantic_diff !== undefined) return { valid: false, reason: "invalid_added_snapshot", path };
        const observed = meaningFingerprint(change.after_source);
        if (observed.fingerprint !== right.fingerprint || observed.amt_version !== right.amt_version) return { valid: false, reason: "added_snapshot_mismatch", path };
      } else if (expectedKind === "removed") {
        if (typeof change.before_source !== "string" || change.after_source !== undefined || change.semantic_diff !== undefined) return { valid: false, reason: "invalid_removed_snapshot", path };
        const observed = meaningFingerprint(change.before_source);
        if (observed.fingerprint !== left.fingerprint || observed.amt_version !== left.amt_version) return { valid: false, reason: "removed_snapshot_mismatch", path };
      } else if (expectedKind === "unchanged") {
        if (change.before_source !== undefined || change.after_source !== undefined || change.semantic_diff !== undefined) return { valid: false, reason: "unexpected_unchanged_payload", path };
      } else {
        if (typeof change.before_source !== "string" || typeof change.after_source !== "string" || !change.semantic_diff) return { valid: false, reason: "invalid_changed_snapshot", path };
        const leftObserved = meaningFingerprint(change.before_source);
        const rightObserved = meaningFingerprint(change.after_source);
        if (leftObserved.fingerprint !== left.fingerprint || rightObserved.fingerprint !== right.fingerprint || leftObserved.amt_version !== left.amt_version || rightObserved.amt_version !== right.amt_version) {
          return { valid: false, reason: "changed_snapshot_mismatch", path };
        }
        const recomputed = semanticDiff(change.before_source, change.after_source);
        if (!sameCanonical(recomputed, change.semantic_diff)) return { valid: false, reason: "semantic_diff_mismatch", path };
      }
    }

    const summary = summarize(proof.changes);
    if (!sameCanonical(summary, proof.change_summary)) return { valid: false, reason: "change_summary_mismatch" };
    return { valid: true, reason: null, summary };
  } catch {
    return { valid: false, reason: "change_verification_error" };
  }
}

export function createSemanticReleaseProof({
  before_manifest,
  before_attestation,
  after_manifest,
  after_attestation,
  lineage,
  before_sources = {},
  after_sources = {},
  private_key_pem,
  signer = null,
  timestamp = new Date().toISOString(),
  release_id = null,
  previous_release_id = null
} = {}) {
  if (!validTimestamp(timestamp)) throw new TypeError("Semantic Release Proof requires a valid generated_at timestamp.");

  const beforeIntegrity = verifyMeaningManifestIntegrity(before_manifest);
  const afterIntegrity = verifyMeaningManifestIntegrity(after_manifest);
  const beforeVerification = verifySignedMeaningManifest(before_attestation, before_manifest);
  const afterVerification = verifySignedMeaningManifest(after_attestation, after_manifest);
  const lineageVerification = verifyMeaningLineage(lineage);
  if (!beforeIntegrity.verified || !afterIntegrity.verified || !beforeVerification.verified || !afterVerification.verified || !lineageVerification.verified) {
    throw new Error("Semantic Release Proof requires valid signed manifests and a valid Meaning Lineage.");
  }

  const privateKey = crypto.createPrivateKey(private_key_pem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new TypeError("Semantic Release Proof requires an Ed25519 private key.");
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  const changes = buildChanges(before_manifest, after_manifest, before_sources, after_sources);
  const proof = {
    protocol: PROTOCOL,
    version: VERSION,
    algorithm: ALGORITHM,
    material_protocol: MATERIAL_PROTOCOL,
    release_id,
    previous_release_id,
    generated_at: timestamp,
    signer,
    public_key_sha256: publicKeyFingerprint(publicKey),
    public_key_pem: publicKeyPem,
    before_manifest: structuredClone(before_manifest),
    before_attestation: structuredClone(before_attestation),
    after_manifest: structuredClone(after_manifest),
    after_attestation: structuredClone(after_attestation),
    lineage: structuredClone(lineage),
    lineage_head_sha256: lineageVerification.head_entry_sha256,
    before_manifest_root_sha256: before_manifest.root_sha256,
    after_manifest_root_sha256: after_manifest.root_sha256,
    semantic_changed: before_manifest.root_sha256 !== after_manifest.root_sha256,
    change_summary: summarize(changes),
    changes
  };
  if (!verifyLineageAdjacency(proof, lineageVerification)) {
    throw new Error("Semantic Release Proof requires the final two lineage entries to match the before/after signed manifests.");
  }
  const material = canonicalJSONStringify(proofMaterial(proof));
  proof.proof_sha256 = sha256(Buffer.from(material, "utf8"));
  proof.signature_base64 = crypto.sign(null, Buffer.from(material, "utf8"), privateKey).toString("base64");
  return proof;
}

export function verifySemanticReleaseProof(proof) {
  const base = {
    verified: false,
    proof_hash_valid: false,
    signature_valid: false,
    public_key_fingerprint_valid: false,
    nested_artifacts_valid: false,
    lineage_adjacency_valid: false,
    changes_valid: false,
    attribution_bound: false,
    signer: null,
    generated_at: null
  };

  try {
    if (!proof || proof.protocol !== PROTOCOL || proof.version !== VERSION || proof.algorithm !== ALGORITHM || proof.material_protocol !== MATERIAL_PROTOCOL) {
      return { ...base, reason: "invalid_release_proof_contract" };
    }
    if (!validTimestamp(proof.generated_at) || !validHash(proof.proof_sha256) || !validHash(proof.public_key_sha256) || !validHash(proof.before_manifest_root_sha256) || !validHash(proof.after_manifest_root_sha256) || !validHash(proof.lineage_head_sha256)) {
      return { ...base, reason: "invalid_release_proof_fields" };
    }
    if (proof.before_manifest?.root_sha256 !== proof.before_manifest_root_sha256 || proof.after_manifest?.root_sha256 !== proof.after_manifest_root_sha256) {
      return { ...base, reason: "release_root_binding_mismatch" };
    }
    if (proof.semantic_changed !== (proof.before_manifest_root_sha256 !== proof.after_manifest_root_sha256)) {
      return { ...base, reason: "semantic_change_flag_mismatch" };
    }

    const nested = verifyNestedArtifacts(proof);
    const nestedValid = nested.beforeIntegrity.verified && nested.afterIntegrity.verified && nested.beforeAttestation.verified && nested.afterAttestation.verified && nested.lineage.verified;
    const adjacencyValid = nestedValid && verifyLineageAdjacency(proof, nested.lineage);
    const changes = verifyChanges(proof);

    const material = canonicalJSONStringify(proofMaterial(proof));
    const expectedHash = sha256(Buffer.from(material, "utf8"));
    const hashValid = expectedHash === proof.proof_sha256;

    const publicKey = crypto.createPublicKey(proof.public_key_pem);
    if (publicKey.asymmetricKeyType !== "ed25519") return { ...base, nested_artifacts_valid: nestedValid, lineage_adjacency_valid: adjacencyValid, changes_valid: changes.valid, proof_hash_valid: hashValid, reason: "unsupported_public_key_type" };
    const fingerprintValid = publicKeyFingerprint(publicKey) === proof.public_key_sha256;
    const signatureValid = crypto.verify(null, Buffer.from(material, "utf8"), publicKey, Buffer.from(proof.signature_base64, "base64"));
    const verified = nestedValid && adjacencyValid && changes.valid && hashValid && fingerprintValid && signatureValid;

    return {
      ...base,
      verified,
      reason: verified ? null : !nestedValid ? "nested_artifact_invalid" : !adjacencyValid ? "lineage_adjacency_invalid" : !changes.valid ? changes.reason : !hashValid ? "proof_hash_mismatch" : !fingerprintValid ? "public_key_fingerprint_mismatch" : "signature_invalid",
      proof_hash_valid: hashValid,
      signature_valid: signatureValid,
      public_key_fingerprint_valid: fingerprintValid,
      nested_artifacts_valid: nestedValid,
      lineage_adjacency_valid: adjacencyValid,
      changes_valid: changes.valid,
      attribution_bound: verified,
      signer: verified ? proof.signer ?? null : null,
      generated_at: verified ? proof.generated_at : null,
      release_id: proof.release_id ?? null,
      previous_release_id: proof.previous_release_id ?? null,
      before_manifest_root_sha256: proof.before_manifest_root_sha256,
      after_manifest_root_sha256: proof.after_manifest_root_sha256,
      semantic_changed: proof.semantic_changed,
      change_summary: changes.summary ?? proof.change_summary,
      lineage_head_sha256: proof.lineage_head_sha256,
      proof_sha256: expectedHash
    };
  } catch {
    return { ...base, reason: "release_proof_verification_error" };
  }
}
