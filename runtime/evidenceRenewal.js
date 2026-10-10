// Append-only, verifier-trusted renewal records for ĀML evidence capsules.
// A valid signature is not an independently trusted witness or a timestamp.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyEvidenceCapsule } from "./evidenceCapsule.js";

const RECORD = "aml-evidence-renewal/1";
const ATTESTATION = "aml-evidence-renewal-attestation/1";
const HEX = /^[a-f0-9]{128}$/;
const FINGERPRINT = /^[a-f0-9]{64}$/;
const UTC_TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/;
const digest = (algorithm, bytes) => crypto.createHash(algorithm).update(bytes).digest("hex");
const canonical = value => canonicalJSONStringify(value);
const ownKeys = (value, expected) => value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join("|") === [...expected].sort().join("|");

const recordFields = ["protocol", "sequence", "previous_root_sha3_512", "created_at", "capsule_sha512", "capsule_sha3_512", "algorithm", "root_sha3_512"];
const witnessFields = ["protocol", "signer", "signed_at", "public_key_pem", "public_key_fingerprint_sha256", "signature_base64"];

function recordPayload(record) {
  const { root_sha3_512, ...payload } = record;
  return payload;
}

function recordRoot(record) {
  return digest("sha3-512", canonical(recordPayload(record)));
}

function attestationMaterial(record, witness) {
  return {
    protocol: ATTESTATION,
    record_root_sha3_512: record.root_sha3_512,
    sequence: record.sequence,
    capsule_sha3_512: record.capsule_sha3_512,
    signer: witness.signer,
    signed_at: witness.signed_at
  };
}

export function createEvidenceRenewal(capsule, options = {}) {
  if (!verifyEvidenceCapsule(capsule).verified) throw new Error("AML_RENEWAL_INVALID_CAPSULE");
  const sequence = options.sequence;
  const previous = options.previous_root_sha3_512 ?? null;
  if (!Number.isSafeInteger(sequence) || sequence < 1 || (sequence === 1 ? previous !== null : typeof previous !== "string" || !HEX.test(previous))) {
    throw new Error("AML_RENEWAL_INVALID_PREDECESSOR");
  }
  const createdAt = options.created_at ?? new Date().toISOString();
  if (typeof createdAt !== "string" || !UTC_TIME.test(createdAt)) {
    throw new Error("AML_RENEWAL_INVALID_TIME");
  }
  const payload = {
    protocol: RECORD,
    sequence,
    previous_root_sha3_512: previous,
    created_at: createdAt,
    capsule_sha512: capsule.digests.sha512,
    capsule_sha3_512: digest("sha3-512", canonical(capsule)),
    algorithm: "SHA3-512"
  };
  return { ...payload, root_sha3_512: digest("sha3-512", canonical(payload)) };
}

export function attestEvidenceRenewal(record, privateKeyPem, options = {}) {
  if (!ownKeys(record, recordFields) || record.protocol !== RECORD || record.algorithm !== "SHA3-512" || recordRoot(record) !== record.root_sha3_512) {
    throw new Error("AML_RENEWAL_INVALID_RECORD");
  }
  const key = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(key);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("AML_RENEWAL_UNSUPPORTED_KEY");
  const signedAt = options.signed_at ?? new Date().toISOString();
  const signer = options.signer ?? null;
  if (typeof signedAt !== "string" || !UTC_TIME.test(signedAt) || (signer !== null && typeof signer !== "string")) {
    throw new Error("AML_RENEWAL_INVALID_ATTESTATION");
  }
  const witness = {
    protocol: ATTESTATION,
    signer,
    signed_at: signedAt,
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    public_key_fingerprint_sha256: digest("sha256", publicKey.export({ type: "spki", format: "der" }))
  };
  return { ...witness, signature_base64: crypto.sign(null, Buffer.from(canonical(attestationMaterial(record, witness)), "utf8"), key).toString("base64") };
}

function verifyWitness(record, witness, trusted, revoked) {
  if (!ownKeys(witness, witnessFields) || witness.protocol !== ATTESTATION ||
      (witness.signer !== null && typeof witness.signer !== "string") || typeof witness.signed_at !== "string" || !UTC_TIME.test(witness.signed_at) ||
      typeof witness.signature_base64 !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(witness.signature_base64)) return null;
  try {
    const key = crypto.createPublicKey(witness.public_key_pem);
    const fingerprint = digest("sha256", key.export({ type: "spki", format: "der" }));
    if (key.asymmetricKeyType !== "ed25519" || witness.public_key_fingerprint_sha256 !== fingerprint ||
        !trusted.has(fingerprint) || revoked.has(fingerprint)) return null;
    const signature = Buffer.from(witness.signature_base64, "base64");
    if (signature.length !== 64 || signature.toString("base64") !== witness.signature_base64) return null;
    return crypto.verify(null, Buffer.from(canonical(attestationMaterial(record, witness)), "utf8"), key, signature) ? fingerprint : null;
  } catch { return null; }
}

export function verifyEvidenceRenewalChain(capsule, entries, policy = {}) {
  const fail = (reason, sequence = null) => ({ verified: false, reason, sequence, freshness_bound: false });
  try {
  if (!verifyEvidenceCapsule(capsule).verified) return fail("invalid_capsule");
  if (!Array.isArray(entries) || entries.length === 0) return fail("empty_chain");
  const threshold = policy.threshold;
  if (!Number.isSafeInteger(threshold) || threshold < 1 || !Array.isArray(policy.trusted_fingerprints) ||
      policy.trusted_fingerprints.length === 0 || policy.trusted_fingerprints.some(value => typeof value !== "string" || !FINGERPRINT.test(value))) {
    return fail("invalid_trust_policy");
  }
  if (policy.revoked_fingerprints !== undefined && (!Array.isArray(policy.revoked_fingerprints) ||
      policy.revoked_fingerprints.some(value => typeof value !== "string" || !FINGERPRINT.test(value)))) return fail("invalid_trust_policy");
  const revoked = new Set(policy.revoked_fingerprints ?? []);
  const capsuleSha3 = digest("sha3-512", canonical(capsule));
  const acceptedHead = policy.accepted_head ?? null;
  if (acceptedHead && (!Number.isSafeInteger(acceptedHead.sequence) || acceptedHead.sequence < 1 || !HEX.test(acceptedHead.root_sha3_512))) return fail("invalid_accepted_head");
  let previous = null;
  let headMatched = acceptedHead === null;
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    const sequence = index + 1;
    const record = entry?.record;
    if (!ownKeys(entry, ["record", "witnesses"]) || !ownKeys(record, recordFields) || record.protocol !== RECORD ||
        record.algorithm !== "SHA3-512" || record.sequence !== sequence || record.previous_root_sha3_512 !== previous ||
        record.capsule_sha512 !== capsule.digests.sha512 || record.capsule_sha3_512 !== capsuleSha3 ||
        typeof record.created_at !== "string" || !UTC_TIME.test(record.created_at) || !HEX.test(record.root_sha3_512) || recordRoot(record) !== record.root_sha3_512) {
      return fail("invalid_record_or_succession", sequence);
    }
    const fingerprints = policy.trusted_fingerprints_by_sequence?.[sequence] ?? policy.trusted_fingerprints;
    if (!Array.isArray(fingerprints) || fingerprints.some(value => typeof value !== "string" || !FINGERPRINT.test(value))) return fail("invalid_trust_policy", sequence);
    const trusted = new Set(fingerprints);
    const seen = new Set();
    if (!Array.isArray(entry.witnesses)) return fail("invalid_witnesses", sequence);
    for (const witness of entry.witnesses) {
      const fingerprint = verifyWitness(record, witness, trusted, revoked);
      if (fingerprint) seen.add(fingerprint);
    }
    if (seen.size < threshold) return fail("quorum_not_met", sequence);
    if (acceptedHead?.sequence === sequence) headMatched = acceptedHead.root_sha3_512 === record.root_sha3_512;
    previous = record.root_sha3_512;
  }
  if (!headMatched) return fail("accepted_head_missing_or_forked");
  return { verified: true, reason: null, sequence: entries.length, head_root_sha3_512: previous,
    freshness_bound: acceptedHead !== null, witness_threshold: threshold };
  } catch {
    return fail("malformed_chain");
  }
}
