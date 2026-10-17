// ĀML key-distinct signed verification quorum — SHIPPED reference prototype.
// Requires valid signed reports over one exact artifact and counts distinct P-256 public keys.
// Distinct keys do not prove distinct people, organizations, independence, or correctness.

import { assertBrowserJSON, canonicalJSONStringifyBrowser, sha256Browser } from './aml-browser-integrity.js';
import { assertCanonicalVerifierPublicKey, verifySignedVerificationReport } from './aml-signed-verification-report.js';
import { verifyWitnessBundle } from './aml-witness-bundle.js';

// These fields describe properties the local witness replay can check. The
// verifier_held_challenge flag describes what the signer did independently;
// replaying with our own held challenge cannot establish that process claim.
const replayableWitnessChecks = [
  'bundle_integrity', 'receipt_integrity', 'evidence_integrity',
  'challenge_freshness', 'challenge_binding', 'session_signature'
];
const requiredWitnessChecks = [...replayableWitnessChecks, 'verifier_held_challenge'];
const inputHashFields = [
  'quorum_sha256', 'policy_sha256', 'witness_bundle_sha256', 'held_challenge_sha256'
];

// The reference report generator emits canonical UTC milliseconds. This
// narrow profile has the same exact interpretation in JS and Python, and
// round-tripping rejects normalized dates such as February 30.
function canonicalReportTime(value) {
  if (typeof value !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? time : null;
}

function conflictingWitnessClaims(report, witness, bundle, replayNow) {
  const conflicts = [];
  if (report.session_key_fingerprint != null &&
      report.session_key_fingerprint !== witness.session_key_fingerprint) {
    conflicts.push('session_key_fingerprint');
  }
  if (report.challenge_expires_at != null &&
      report.challenge_expires_at !== witness.challenge_expires_at) {
    conflicts.push('challenge_expires_at');
  }
  if (report.checked_at != null) {
    const checked = canonicalReportTime(report.checked_at);
    const issued = Date.parse(bundle.challenge.issued_at);
    const assembled = canonicalReportTime(bundle.created_at);
    const attested = canonicalReportTime(bundle.attestation.issued_at);
    const expires = Date.parse(witness.challenge_expires_at);
    if (checked === null || assembled === null || attested === null ||
        checked < Math.max(issued, assembled, attested) ||
        checked > expires || checked > replayNow) {
      conflicts.push('checked_at');
    }
  }
  if (!report.checks || typeof report.checks !== 'object' || Array.isArray(report.checks)) {
    conflicts.push('checks');
  } else {
    for (const [name, value] of Object.entries(report.checks)) {
      if (typeof value !== 'boolean') conflicts.push(`checks.${name}`);
    }
    for (const name of replayableWitnessChecks) {
      if (Object.hasOwn(report.checks, name) && report.checks[name] !== witness.checks[name] &&
          !conflicts.includes(`checks.${name}`)) {
        conflicts.push(`checks.${name}`);
      }
    }
  }
  return conflicts;
}

// Policy /4 requires signed affirmative claims from each trusted positive
// report. These are assertions by the signer; replay separately checks the
// reference steps and cannot establish the signer's own process.
function unsatisfiedWitnessClaims(report) {
  const fields = [];
  for (const name of ['session_key_fingerprint', 'challenge_expires_at', 'checked_at']) {
    if (report[name] == null) fields.push(name);
  }
  for (const name of requiredWitnessChecks) {
    if (report.checks?.[name] !== true) fields.push(`checks.${name}`);
  }
  return fields;
}

// Envelope fingerprints bind the complete JWK JSON, including optional metadata.
// For quorum identity, hash the P-256 public point instead: one key must count once
// even when the same JWK carries different labels, key_ops, or other metadata.
async function verifierKeyMaterialFingerprint(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
      typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('AML_SIGNED_QUORUM_KEY_MATERIAL_INVALID');
  }
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')),
    character => character.charCodeAt(0));
  const x = decode(jwk.x);
  const y = decode(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error('AML_SIGNED_QUORUM_KEY_MATERIAL_INVALID');
  const rawPoint = new Uint8Array(65);
  rawPoint[0] = 4;
  rawPoint.set(x, 1);
  rawPoint.set(y, 33);
  const digest = await crypto.subtle.digest('SHA-256', rawPoint);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// Derive both identifiers from a public JWK obtained through the buyer's own
// channel. This calculates identifiers; it does not identify or authorize its
// holder. The full-document fingerprint includes optional JWK metadata.
export async function fingerprintVerifierPublicKey(jwk) {
  assertBrowserJSON(jwk);
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || Object.hasOwn(jwk, 'd')) {
    throw new Error('AML_SIGNED_QUORUM_PUBLIC_KEY_INVALID');
  }
  assertCanonicalVerifierPublicKey(jwk);
  const imported = await crypto.subtle.importKey('jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  if (imported.type !== 'public') throw new Error('AML_SIGNED_QUORUM_PUBLIC_KEY_INVALID');
  return {
    verifier_key_fingerprint: await sha256Browser(jwk),
    key_material_fingerprint: await verifierKeyMaterialFingerprint(jwk)
  };
}

export async function createSignedVerificationQuorum(signedReports, { threshold = 2 } = {}) {
  if (!Array.isArray(signedReports) || signedReports.length === 0) throw new Error('AML_SIGNED_QUORUM_REPORTS_REQUIRED');
  if (signedReports.length > 64) throw new Error('AML_SIGNED_QUORUM_TOO_MANY_REPORTS');
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error('AML_SIGNED_QUORUM_THRESHOLD_INVALID');
  assertBrowserJSON(signedReports);

  const checks = [];
  for (const envelope of signedReports) {
    const signature = await verifySignedVerificationReport(envelope);
    checks.push({ envelope, signature });
  }

  const signed = checks.filter(({ signature }) => signature.valid);
  if (!signed.length) throw new Error('AML_SIGNED_QUORUM_NO_VALID_SIGNED_REPORTS');

  // Every authenticated report must identify the same artifact and carry a
  // boolean verdict. A signature over malformed metadata is not an endorsement.
  for (const { envelope } of signed) {
    const report = envelope.report;
    if (report.prototype !== true || typeof report.verifier !== 'string' || !report.verifier.trim()) {
      throw new Error('AML_SIGNED_QUORUM_REPORT_INVALID');
    }
    if (typeof report.artifact_type !== 'string' || !report.artifact_type.trim()) {
      throw new Error('AML_SIGNED_QUORUM_ARTIFACT_TYPE_REQUIRED');
    }
    if (typeof report.artifact_hash !== 'string' || !report.artifact_hash.trim()) {
      throw new Error('AML_SIGNED_QUORUM_ARTIFACT_HASH_REQUIRED');
    }
    if (typeof report.valid !== 'boolean') {
      throw new Error('AML_SIGNED_QUORUM_REPORT_VERDICT_INVALID');
    }
    if (typeof report.reason !== 'string' || !report.reason.trim()) {
      throw new Error('AML_SIGNED_QUORUM_REPORT_REASON_INVALID');
    }
  }

  const artifactType = signed[0].envelope.report.artifact_type;
  const artifactHash = signed[0].envelope.report.artifact_hash;

  for (const { envelope } of signed) {
    if (envelope.report.artifact_type !== artifactType) throw new Error('AML_SIGNED_QUORUM_ARTIFACT_TYPE_MISMATCH');
    if (envelope.report.artifact_hash !== artifactHash) throw new Error('AML_SIGNED_QUORUM_ARTIFACT_HASH_MISMATCH');
  }

  // Only keys that signed a valid verdict count toward the endorsement quorum.
  // A correctly signed INVALID report is authenticated dissent, not support.
  const validEndorserKeys = new Set();
  let validReports = 0;
  let invalidReports = 0;
  const reasons = new Set();

  for (const { envelope, signature } of checks) {
    if (!signature.valid) {
      invalidReports += 1;
      reasons.add(signature.reason);
      continue;
    }

    if (envelope.report.valid) {
      validReports += 1;
      validEndorserKeys.add(await verifierKeyMaterialFingerprint(envelope.verifier_public_key_jwk));
    } else {
      invalidReports += 1;
      reasons.add(envelope.report.reason);
    }
  }

  return {
    schema: 'aml-signed-verification-quorum/1',
    prototype: true,
    artifact_type: artifactType,
    artifact_hash: artifactHash,
    threshold,
    signed_reports: signedReports,
    summary: {
      distinct_keys: validEndorserKeys.size,
      valid_signatures: checks.filter(({ signature }) => signature.valid).length,
      valid_reports: validReports,
      invalid_reports: invalidReports,
      threshold_met: validReports >= threshold && validEndorserKeys.size >= threshold,
      unanimous: invalidReports === 0 && validReports === signedReports.length,
      disagreement_reasons: [...reasons]
    },
    claim_boundary: 'Threshold agreement means enough supplied reports were validly signed by distinct public-key fingerprints over the same exact artifact and reported valid. Correctly signed invalid reports are authenticated dissent and never count toward the endorsement quorum. Distinct keys do not prove distinct people, organizations, independence, authorization, certification, or correctness.'
  };
}

export function validateSignedVerificationQuorumPolicy(policy) {
  assertBrowserJSON(policy);
  const vetoDissent = policy?.schema === 'aml-signed-quorum-held-policy/5';
  const completeClaims = vetoDissent || policy?.schema === 'aml-signed-quorum-held-policy/4';
  const materialPinned = completeClaims || policy?.schema === 'aml-signed-quorum-held-policy/3';
  const grouped = materialPinned || policy?.schema === 'aml-signed-quorum-held-policy/2';
  const fields = grouped
    ? ['artifact_hash', 'artifact_type', 'group_threshold', 'prototype', 'schema', 'threshold', 'trusted_keys']
    : ['artifact_hash', 'artifact_type', 'prototype', 'schema', 'threshold', 'trusted_key_fingerprints'];
  if (completeClaims) fields.push('require_complete_witness_claims');
  if (vetoDissent) fields.push('reject_trusted_dissent');
  if (!policy || Array.isArray(policy) || Object.keys(policy).sort().join('|') !== fields.sort().join('|') ||
      !['aml-signed-quorum-held-policy/1', 'aml-signed-quorum-held-policy/2',
        'aml-signed-quorum-held-policy/3', 'aml-signed-quorum-held-policy/4',
        'aml-signed-quorum-held-policy/5'].includes(policy.schema) ||
      policy.prototype !== true || (completeClaims &&
        (policy.require_complete_witness_claims !== true || policy.artifact_type !== 'aml-witness-bundle/1')) ||
      (vetoDissent && policy.reject_trusted_dissent !== true)) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_INVALID');
  }
  if (typeof policy.artifact_type !== 'string' || !policy.artifact_type.trim() ||
      typeof policy.artifact_hash !== 'string' || !/^[a-f0-9]{64}$/.test(policy.artifact_hash)) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_ARTIFACT_INVALID');
  }
  if (grouped && (!Array.isArray(policy.trusted_keys) || policy.trusted_keys.some(entry =>
    !entry || Array.isArray(entry) || typeof entry !== 'object' ||
    Object.keys(entry).sort().join('|') !== (materialPinned
      ? 'key_material_fingerprint|trust_group|verifier_key_fingerprint'
      : 'trust_group|verifier_key_fingerprint') ||
    typeof entry.trust_group !== 'string' ||
    !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(entry.trust_group)))) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_GROUPS_INVALID');
  }
  const keys = grouped ? policy.trusted_keys.map(entry => entry.verifier_key_fingerprint)
    : policy.trusted_key_fingerprints;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 64 ||
      keys.some(key => typeof key !== 'string' || !/^[a-f0-9]{64}$/.test(key)) ||
      new Set(keys).size !== keys.length) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_KEYS_INVALID');
  }
  if (materialPinned) {
    const materials = policy.trusted_keys.map(entry => entry.key_material_fingerprint);
    if (materials.some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) ||
        new Set(materials).size !== materials.length) {
      throw new Error('AML_SIGNED_QUORUM_POLICY_MATERIAL_INVALID');
    }
  }
  if (!Number.isInteger(policy.threshold) || policy.threshold < 1 || policy.threshold > keys.length) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_THRESHOLD_INVALID');
  }
  if (grouped) {
    const groups = new Set(policy.trusted_keys.map(entry => entry.trust_group));
    if (!Number.isInteger(policy.group_threshold) || policy.group_threshold < 1 ||
        policy.group_threshold > groups.size) {
      throw new Error('AML_SIGNED_QUORUM_POLICY_GROUP_THRESHOLD_INVALID');
    }
  }
  return policy;
}

function validateInputExpectations(expectations, { policy, witnessBundle }) {
  assertBrowserJSON(expectations);
  if (!expectations || typeof expectations !== 'object' || Array.isArray(expectations) ||
      expectations.schema !== 'aml-signed-quorum-input-expectations/1' ||
      expectations.prototype !== true || expectations.canonicalization !== 'sorted-json-v1' ||
      Object.keys(expectations).some(key => ![
        'schema', 'prototype', 'canonicalization', ...inputHashFields
      ].includes(key))) {
    throw new Error('AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_INVALID');
  }
  const pinned = inputHashFields.filter(field => Object.hasOwn(expectations, field));
  if (!pinned.length || pinned.some(field => typeof expectations[field] !== 'string' ||
      !/^[a-f0-9]{64}$/.test(expectations[field]))) {
    throw new Error('AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_INVALID');
  }
  if ((policy === undefined && pinned.includes('policy_sha256')) ||
      (witnessBundle === undefined && pinned.some(field =>
        ['witness_bundle_sha256', 'held_challenge_sha256'].includes(field)))) {
    throw new Error('AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_MISSING_INPUT');
  }
  return pinned;
}

export async function verifySignedVerificationQuorum(quorum, {
  policy, witnessBundle, expectedChallenge, expectedInputFingerprints
} = {}) {
  // A verifier-held policy is configuration, not part of the untrusted quorum.
  // Reject malformed configuration as a usage error before checking the quorum.
  if (policy !== undefined) validateSignedVerificationQuorumPolicy(policy);
  if ((witnessBundle === undefined) !== (expectedChallenge === undefined)) {
    throw new Error('AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED');
  }
  if (['aml-signed-quorum-held-policy/4', 'aml-signed-quorum-held-policy/5']
    .includes(policy?.schema) && witnessBundle === undefined) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED');
  }
  const pinnedInputs = expectedInputFingerprints === undefined ? [] :
    validateInputExpectations(expectedInputFingerprints, { policy, witnessBundle });
  const reject = (reason) => ({
    valid: false, reason, threshold_met: false,
    ...(policy === undefined ? {} : { policy_met: false }),
    ...(witnessBundle === undefined ? {} : { witness_met: false, replayable_claims_consistent: false }),
    ...(expectedInputFingerprints === undefined ? {} : { inputs_met: false })
  });
  try {
    assertBrowserJSON(quorum);
    if (!quorum || quorum.schema !== 'aml-signed-verification-quorum/1') {
      return reject('AML_SIGNED_QUORUM_INVALID');
    }
    const rebuilt = await createSignedVerificationQuorum(quorum.signed_reports, { threshold: quorum.threshold });
    const valid = canonicalJSONStringifyBrowser(quorum) === canonicalJSONStringifyBrowser(rebuilt);
    const result = {
      valid,
      reason: valid ? 'AML_SIGNED_QUORUM_VALID' : 'AML_SIGNED_QUORUM_MISMATCH',
      threshold_met: valid && rebuilt.summary.threshold_met,
      quorum: rebuilt
    };
    if (policy !== undefined) {
      if (!valid) {
        result.policy_met = false;
      } else {
        const artifactMatches = rebuilt.artifact_type === policy.artifact_type &&
          rebuilt.artifact_hash === policy.artifact_hash;
        const materialPinned = ['aml-signed-quorum-held-policy/3',
          'aml-signed-quorum-held-policy/4', 'aml-signed-quorum-held-policy/5']
          .includes(policy.schema);
        const vetoDissent = policy.schema === 'aml-signed-quorum-held-policy/5';
        const grouped = materialPinned || policy.schema === 'aml-signed-quorum-held-policy/2';
        const assignments = grouped ? new Map(policy.trusted_keys.map(entry =>
          [entry.verifier_key_fingerprint, entry])) : null;
        const allowed = new Set(grouped ? assignments.keys() : policy.trusted_key_fingerprints);
        const trusted = new Set();
        const materialGroups = new Map();
        const conflictingMaterials = new Set();
        const mismatchedPins = new Set();
        const trustedDissent = [];
        if (artifactMatches) {
          for (const envelope of rebuilt.signed_reports) {
            if (envelope?.report?.valid !== true || !allowed.has(envelope.verifier_key_fingerprint)) continue;
            if ((await verifySignedVerificationReport(envelope)).valid) {
              const material = await verifierKeyMaterialFingerprint(envelope.verifier_public_key_jwk);
              if (materialPinned && assignments.get(envelope.verifier_key_fingerprint)
                .key_material_fingerprint !== material) {
                mismatchedPins.add(envelope.verifier_key_fingerprint);
                continue;
              }
              trusted.add(material);
              if (grouped) {
                const group = assignments.get(envelope.verifier_key_fingerprint).trust_group;
                if (materialGroups.has(material) && materialGroups.get(material) !== group) {
                  conflictingMaterials.add(material);
                } else {
                  materialGroups.set(material, group);
                }
              }
            }
          }
        }
        // The veto follows pinned key material, even when a validly signed
        // dissent uses a different JWK metadata label than the held envelope.
        // Only authenticated, supplied negative reports can trigger it.
        if (artifactMatches && vetoDissent) {
          const pinnedMaterials = new Set(policy.trusted_keys.map(entry =>
            entry.key_material_fingerprint));
          for (const [index, envelope] of rebuilt.signed_reports.entries()) {
            if (envelope?.report?.valid !== false ||
                !(await verifySignedVerificationReport(envelope)).valid) continue;
            const material = await verifierKeyMaterialFingerprint(envelope.verifier_public_key_jwk);
            if (pinnedMaterials.has(material)) {
              trustedDissent.push({ report_index: index, key_material_fingerprint: material });
            }
          }
        }
        const distinctGroups = grouped ? new Set([...materialGroups].filter(([material]) =>
          !conflictingMaterials.has(material)).map(([, group]) => group)).size : 0;
        result.policy_met = artifactMatches && trusted.size >= policy.threshold &&
          (!grouped || (distinctGroups >= policy.group_threshold && conflictingMaterials.size === 0)) &&
          (!materialPinned || mismatchedPins.size === 0) &&
          (!vetoDissent || trustedDissent.length === 0);
        result.policy_evaluation = {
          artifact_matches: artifactMatches,
          distinct_trusted_keys: trusted.size,
          threshold: policy.threshold,
          ...(grouped ? {
            distinct_trust_groups: distinctGroups,
            group_threshold: policy.group_threshold,
            conflicting_key_material_fingerprints: [...conflictingMaterials]
          } : {}),
          ...(materialPinned ? { mismatched_key_fingerprints: [...mismatchedPins] } : {}),
          ...(vetoDissent ? { trusted_dissent: trustedDissent } : {})
        };
      }
    }
    if (witnessBundle !== undefined) {
      // Snapshot the local clock once for the freshness decision. The timestamp
      // describes this replay, not when a signer checked or a trusted time source.
      const replayNow = Date.now();
      const witness = await verifyWitnessBundle(witnessBundle, { expectedChallenge, now: replayNow });
      const artifactMatches = rebuilt.artifact_type === 'aml-witness-bundle/1' &&
        rebuilt.artifact_hash === witnessBundle?.integrity?.value;
      result.witness_met = valid && witness.valid &&
        witness.checks?.verifier_held_challenge === true && artifactMatches;
      result.witness_evaluation = {
        evaluated_at: new Date(replayNow).toISOString(),
        clock_source: 'local_system',
        local_bundle_valid: witness.valid,
        reason: witness.reason,
        retained_challenge_matched: witness.checks?.verifier_held_challenge === true,
        artifact_matches: artifactMatches
      };
      // A successful replay verifies the artifact, but signed reports can also
      // assert conflicting session details or step results. Check only the
      // authenticated positive reports; invalid signatures and dissent are not
      // endorsements. Unknown check names and signer process claims cannot be
      // inferred from the reference replay.
      const conflicts = [];
      let positiveSignedReports = 0;
      if (result.witness_met) {
        for (const [index, envelope] of rebuilt.signed_reports.entries()) {
          if (envelope?.report?.valid !== true ||
              !(await verifySignedVerificationReport(envelope)).valid) continue;
          positiveSignedReports += 1;
          const fields = conflictingWitnessClaims(envelope.report, witness, witnessBundle, replayNow);
          if (fields.length) conflicts.push({ report_index: index, fields });
        }
      }
      result.replayable_claims_consistent = result.witness_met && conflicts.length === 0;
      result.replayable_claims_evaluation = {
        checked: result.witness_met,
        positive_signed_reports: positiveSignedReports,
        conflicts
      };
    }
    if (['aml-signed-quorum-held-policy/4', 'aml-signed-quorum-held-policy/5']
      .includes(policy?.schema) && valid) {
      const unsatisfied = [];
      if (result.witness_met) {
        const assignments = new Map(policy.trusted_keys.map(entry =>
          [entry.verifier_key_fingerprint, entry.key_material_fingerprint]));
        for (const [index, envelope] of rebuilt.signed_reports.entries()) {
          if (envelope?.report?.valid !== true ||
              !(await verifySignedVerificationReport(envelope)).valid ||
              !assignments.has(envelope.verifier_key_fingerprint)) continue;
          if (await verifierKeyMaterialFingerprint(envelope.verifier_public_key_jwk) !==
              assignments.get(envelope.verifier_key_fingerprint)) continue;
          const fields = unsatisfiedWitnessClaims(envelope.report);
          if (fields.length) unsatisfied.push({ report_index: index, fields });
        }
      }
      result.policy_evaluation.complete_claims_checked = result.witness_met;
      result.policy_evaluation.unsatisfied_claims = unsatisfied;
      result.policy_met = result.policy_met && result.witness_met &&
        result.replayable_claims_consistent && unsatisfied.length === 0;
    }
    // Identify the exact JSON inputs evaluated, including buyer-held inputs
    // that are intentionally absent from the signed quorum. Hash the canonical
    // JSON text explicitly: sha256Browser treats a string as raw bytes.
    // A live non-JSON witness input can still be rejected by the replay without
    // changing the quorum's independent validity result; it has no fingerprint.
    let hashable = true;
    if (witnessBundle !== undefined) {
      try {
        assertBrowserJSON(witnessBundle);
        assertBrowserJSON(expectedChallenge);
      } catch (error) {
        if (!(error instanceof TypeError)) throw error;
        hashable = false;
      }
    }
    if (hashable) {
      result.input_fingerprints = {
        canonicalization: 'sorted-json-v1',
        quorum_sha256: await sha256Browser(canonicalJSONStringifyBrowser(quorum)),
        ...(policy === undefined ? {} : {
          policy_sha256: await sha256Browser(canonicalJSONStringifyBrowser(policy))
        }),
        ...(witnessBundle === undefined ? {} : {
          witness_bundle_sha256: await sha256Browser(canonicalJSONStringifyBrowser(witnessBundle)),
          held_challenge_sha256: await sha256Browser(canonicalJSONStringifyBrowser(expectedChallenge))
        })
      };
    }
    if (expectedInputFingerprints !== undefined) {
      const unavailable = pinnedInputs.filter(field =>
        !Object.hasOwn(result.input_fingerprints ?? {}, field));
      const mismatched = pinnedInputs.filter(field =>
        !unavailable.includes(field) &&
        expectedInputFingerprints[field] !== result.input_fingerprints[field]);
      result.inputs_met = unavailable.length === 0 && mismatched.length === 0;
      result.input_evaluation = {
        expectations_sha256: await sha256Browser(canonicalJSONStringifyBrowser(expectedInputFingerprints)),
        checked: pinnedInputs, mismatched, unavailable
      };
    }
    return result;
  } catch (error) {
    return reject(error?.message || 'AML_SIGNED_QUORUM_VERIFY_ERROR');
  }
}
