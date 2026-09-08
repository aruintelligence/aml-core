// ĀML Web Worker verifier — SHIPPED reference prototype.
// Verifies aml-witness-bundle/1 without DOM access.

import { verifyWitnessBundle } from './aml-witness-bundle.js';
import { witnessVerificationReport } from './aml-verification-report.js';

self.addEventListener('message', async (event) => {
  const { id = null, bundle, now = Date.now() } = event.data || {};
  try {
    const result = await verifyWitnessBundle(bundle, { now });
    const report = witnessVerificationReport(bundle, result, { verifier: 'aml-web-worker' });
    self.postMessage({ id, report });
  } catch (error) {
    self.postMessage({
      id,
      report: {
        schema: 'aml-verification-report/1',
        prototype: true,
        verifier: 'aml-web-worker',
        artifact_type: 'aml-witness-bundle/1',
        valid: false,
        reason: error?.message || 'AML_WORKER_VERIFY_ERROR',
        checked_at: new Date().toISOString(),
        artifact_hash: bundle?.integrity?.value || null,
        session_key_fingerprint: bundle?.attestation?.session_key_fingerprint || null,
        challenge_expires_at: bundle?.challenge?.expires_at || null,
        checks: {},
        notes: ['Worker isolation removes application DOM access; it is not a hardware or operating-system trust boundary.']
      }
    });
  }
});
