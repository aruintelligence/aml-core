import { verifySignedGovernanceStreamTranscript } from "./governanceTranscriptSignature.js";

export const AML_GOVERNANCE_WITNESS_QUORUM = "aml-governance-witness-quorum/1";
export const AML_GOVERNANCE_WITNESS_QUORUM_VERIFICATION = "aml-governance-witness-quorum-verification/1";

function normalizePolicy(policy = {}) {
  const threshold = Number.isInteger(policy.threshold) && policy.threshold > 0 ? policy.threshold : 1;
  return {
    threshold,
    trusted_fingerprints: Array.isArray(policy.trusted_fingerprints) ? [...new Set(policy.trusted_fingerprints)] : [],
    revoked_fingerprints: Array.isArray(policy.revoked_fingerprints) ? [...new Set(policy.revoked_fingerprints)] : [],
    required_scope: policy.required_scope || null,
    require_unique_keys: policy.require_unique_keys !== false
  };
}

function transcriptIdentity(signed) {
  const transcript = signed?.transcript;
  return transcript?.root_sha256 || null;
}

export function evaluateGovernanceWitnessQuorum(signedTranscripts, policy = {}) {
  if (!Array.isArray(signedTranscripts)) {
    throw new TypeError("signedTranscripts must be an array");
  }

  const normalized = normalizePolicy(policy);
  const revoked = new Set(normalized.revoked_fingerprints);
  const trusted = new Set(normalized.trusted_fingerprints);
  const seenKeys = new Set();
  const witnessResults = [];
  const rootGroups = new Map();

  for (let index = 0; index < signedTranscripts.length; index += 1) {
    const signed = signedTranscripts[index];
    const verification = verifySignedGovernanceStreamTranscript(signed, {
      trusted_fingerprints: normalized.trusted_fingerprints,
      require_trusted_key: normalized.trusted_fingerprints.length > 0
    });
    const fingerprint = verification.public_key_fingerprint_sha256 || null;
    const root = transcriptIdentity(signed);
    const scopeOk = !normalized.required_scope || verification.scope === normalized.required_scope;
    const revokedKey = fingerprint ? revoked.has(fingerprint) : false;
    const duplicateKey = normalized.require_unique_keys && fingerprint ? seenKeys.has(fingerprint) : false;
    const trustedKey = normalized.trusted_fingerprints.length === 0 ? verification.signature_valid : trusted.has(fingerprint);
    const eligible = Boolean(
      verification.transcript_valid &&
      verification.replay_valid &&
      verification.signature_valid &&
      trustedKey &&
      scopeOk &&
      !revokedKey &&
      !duplicateKey &&
      root
    );

    if (fingerprint && !duplicateKey) seenKeys.add(fingerprint);
    if (eligible) {
      if (!rootGroups.has(root)) rootGroups.set(root, []);
      rootGroups.get(root).push(index);
    }

    witnessResults.push({
      index,
      eligible,
      transcript_root_sha256: root,
      fingerprint,
      signer: verification.signer || null,
      scope: verification.scope || null,
      transcript_valid: verification.transcript_valid,
      replay_valid: verification.replay_valid,
      signature_valid: verification.signature_valid,
      trusted_key: trustedKey,
      revoked_key: revokedKey,
      duplicate_key: duplicateKey,
      scope_valid: scopeOk,
      errors: verification.errors || []
    });
  }

  const groups = [...rootGroups.entries()]
    .map(([root_sha256, indexes]) => ({ root_sha256, witness_indexes: indexes, count: indexes.length }))
    .sort((a, b) => b.count - a.count || a.root_sha256.localeCompare(b.root_sha256));
  const winning = groups[0] || null;
  const quorumMet = Boolean(winning && winning.count >= normalized.threshold);
  const conflictingEligibleRoots = groups.length > 1;

  return {
    protocol: AML_GOVERNANCE_WITNESS_QUORUM,
    policy: normalized,
    quorum_met: quorumMet,
    threshold: normalized.threshold,
    winning_transcript_root_sha256: quorumMet ? winning.root_sha256 : null,
    winning_witness_count: winning?.count || 0,
    eligible_witness_count: witnessResults.filter((item) => item.eligible).length,
    conflicting_eligible_roots: conflictingEligibleRoots,
    root_groups: groups,
    witnesses: witnessResults
  };
}

export function verifyGovernanceWitnessQuorum(result) {
  const errors = [];
  if (!result || result.protocol !== AML_GOVERNANCE_WITNESS_QUORUM) {
    return { protocol: AML_GOVERNANCE_WITNESS_QUORUM_VERIFICATION, valid: false, errors: ["unsupported quorum protocol"] };
  }
  if (!Number.isInteger(result.threshold) || result.threshold < 1) errors.push("invalid threshold");
  if (!Array.isArray(result.witnesses)) errors.push("witnesses must be an array");
  if (!Array.isArray(result.root_groups)) errors.push("root_groups must be an array");

  const eligible = Array.isArray(result.witnesses) ? result.witnesses.filter((item) => item?.eligible) : [];
  const groups = new Map();
  for (const witness of eligible) {
    const root = witness.transcript_root_sha256;
    if (!root) continue;
    groups.set(root, (groups.get(root) || 0) + 1);
  }
  const max = groups.size ? Math.max(...groups.values()) : 0;
  const expectedMet = max >= result.threshold;
  if (result.quorum_met !== expectedMet) errors.push("quorum_met does not match witness evidence");
  if (result.winning_witness_count !== max) errors.push("winning_witness_count mismatch");
  if (result.quorum_met && !result.winning_transcript_root_sha256) errors.push("winning transcript root required when quorum is met");

  return {
    protocol: AML_GOVERNANCE_WITNESS_QUORUM_VERIFICATION,
    valid: errors.length === 0,
    quorum_met: expectedMet,
    eligible_witness_count: eligible.length,
    distinct_eligible_roots: groups.size,
    errors
  };
}
