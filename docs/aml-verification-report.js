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
  const checkNames = [
    'bundle_integrity', 'receipt_integrity', 'evidence_integrity',
    'challenge_freshness', 'challenge_binding', 'session_signature',
    'verifier_held_challenge'
  ];
  const recordedChecks = result?.checks && typeof result.checks === 'object' ? result.checks : null;
  const checks = Object.fromEntries(checkNames.map((name) => [name,
    recordedChecks ? recordedChecks[name] === true : name !== 'verifier_held_challenge' && result?.valid === true
  ]));
  return createVerificationReport({
    verifier,
    artifact_type: 'aml-witness-bundle/1',
    result,
    artifact_hash: bundle?.integrity?.value || null,
    session_key_fingerprint: bundle?.attestation?.session_key_fingerprint || null,
    challenge_expires_at: bundle?.challenge?.expires_at || null,
    checks,
    notes: [
      'A true check records a project-defined verification step as passed; false means it failed or was not reached.',
      'verifier_held_challenge is true only when a separate retained challenge was supplied and matched.',
      'It does not prove identity, truthful declared intent, policy quality, official AML authorization, or regulatory compliance.'
    ]
  });
}
