// ĀML verification report — SHIPPED reference prototype.
// Normalizes verifier outcomes into one portable result object.
// A report states which project-defined checks passed; it is not certification or identity proof.

export function createVerificationReport({
  verifier,
  artifact_type,
  result,
  artifact_hash = null,
  session_key_fingerprint = null,
  challenge_expires_at = null,
  checks = {},
  notes = [],
  checked_at = new Date().toISOString()
} = {}) {
  if (!verifier || !artifact_type || !result || typeof result.valid !== 'boolean') {
    throw new Error('AML_VERIFICATION_REPORT_INPUT_INVALID');
  }
  return {
    schema: 'aml-verification-report/1',
    prototype: true,
    verifier,
    artifact_type,
    valid: result.valid,
    reason: String(result.reason || (result.valid ? 'AML_VERIFICATION_VALID' : 'AML_VERIFICATION_INVALID')),
    checked_at,
    artifact_hash,
    session_key_fingerprint,
    challenge_expires_at,
    checks: { ...checks },
    notes: [...notes].slice(0, 20)
  };
}

export function witnessVerificationReport(bundle, result, { verifier = 'aml-reference-js' } = {}) {
  return createVerificationReport({
    verifier,
    artifact_type: 'aml-witness-bundle/1',
    result,
    artifact_hash: bundle?.integrity?.value || null,
    session_key_fingerprint: bundle?.attestation?.session_key_fingerprint || null,
    challenge_expires_at: bundle?.challenge?.expires_at || null,
    checks: {
      bundle_integrity: result?.valid || result?.reason !== 'AML_WITNESS_BUNDLE_HASH_MISMATCH',
      receipt_integrity: result?.valid || !String(result?.reason || '').includes('RECEIPT'),
      evidence_integrity: result?.valid || !String(result?.reason || '').includes('EVIDENCE'),
      challenge_freshness: result?.valid || result?.reason !== 'AML_CHALLENGE_EXPIRED',
      challenge_binding: result?.valid || result?.reason !== 'AML_SESSION_CHALLENGE_MISMATCH',
      session_signature: result?.valid || result?.reason !== 'AML_SESSION_SIGNATURE_INVALID'
    },
    notes: [
      'PASS means the project-defined integrity, freshness, binding, and signature checks represented by this verifier succeeded.',
      'It does not prove identity, truthful declared intent, policy quality, official AML authorization, or regulatory compliance.'
    ]
  });
}
