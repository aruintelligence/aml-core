import { assertBrowserJSON, canonicalJSONStringifyBrowser, sha256Browser,
  snapshotBrowserJSON, verifyBrowserReceipt } from './aml-browser-integrity.js';

let evidenceRevision = 0;

function currentViolations() {
  return [...(globalThis.__AML_ZONE_VIOLATIONS__ || [])];
}

export function browserEvidencePayload(evidence) {
  assertBrowserJSON(evidence);
  if (!evidence || evidence.schema !== 'aml-browser-evidence/1') {
    throw new Error('AML_BROWSER_EVIDENCE_INVALID');
  }
  const { integrity, ...payload } = evidence;
  return payload;
}

export async function createBrowserEvidence(
  receipt = globalThis.__AML_RECEIPT__,
  { url = globalThis.location?.href || 'about:blank' } = {}
) {
  if (!receipt?.integrity) throw new Error('AML_BROWSER_EVIDENCE_REQUIRES_SEALED_RECEIPT');
  try { receipt = snapshotBrowserJSON(receipt); }
  catch { throw new Error('AML_BROWSER_EVIDENCE_RECEIPT_INVALID'); }
  url = snapshotBrowserJSON(url);
  const receiptCheck = await verifyBrowserReceipt(receipt);
  if (!receiptCheck.valid) throw new Error('AML_BROWSER_EVIDENCE_RECEIPT_INVALID');

  evidenceRevision += 1;
  const evidence = {
    schema: 'aml-browser-evidence/1',
    prototype: true,
    revision: evidenceRevision,
    url,
    generated_at: new Date().toISOString(),
    receipt,
    zone_violations: snapshotBrowserJSON(currentViolations())
  };

  evidence.integrity = {
    schema: 'aml-integrity/1',
    algorithm: 'SHA-256',
    canonicalization: 'sorted-json-v1',
    value: await sha256Browser(browserEvidencePayload(evidence))
  };

  globalThis.__AML_EVIDENCE__ = evidence;
  globalThis.__AML_EVIDENCE_HISTORY__ ||= [];
  globalThis.__AML_EVIDENCE_HISTORY__.push(evidence);
  if (globalThis.__AML_EVIDENCE_HISTORY__.length > 50) {
    globalThis.__AML_EVIDENCE_HISTORY__.shift();
  }

  if (globalThis.document?.dispatchEvent && globalThis.CustomEvent) {
    document.dispatchEvent(new CustomEvent('aml-evidence', {
      bubbles: false,
      detail: evidence
    }));
  }
  return evidence;
}

export async function verifyBrowserEvidence(evidence) {
  try {
    evidence = snapshotBrowserJSON(evidence);
    if (!evidence?.integrity || evidence.integrity.schema !== 'aml-integrity/1') {
      return { valid: false, reason: 'AML_BROWSER_EVIDENCE_UNSEALED' };
    }
    if (evidence.integrity.algorithm !== 'SHA-256') {
      return { valid: false, reason: 'AML_BROWSER_EVIDENCE_ALGORITHM_UNSUPPORTED' };
    }
    if (evidence.integrity.canonicalization !== 'sorted-json-v1') {
      return { valid: false, reason: 'AML_BROWSER_EVIDENCE_CANONICALIZATION_UNSUPPORTED' };
    }
    if (Object.keys(evidence.integrity).sort().join('|') !== 'algorithm|canonicalization|schema|value' ||
        !/^[a-f0-9]{64}$/.test(evidence.integrity.value)) {
      return { valid: false, reason: 'AML_BROWSER_EVIDENCE_INTEGRITY_INVALID' };
    }
    const receipt = await verifyBrowserReceipt(evidence.receipt);
    if (!receipt.valid) {
      return { valid: false, reason: 'AML_BROWSER_EVIDENCE_RECEIPT_INVALID', receipt };
    }
    const expected = await sha256Browser(browserEvidencePayload(evidence));
    const valid = expected === evidence.integrity.value;
    return {
      valid,
      reason: valid ? 'AML_BROWSER_EVIDENCE_VALID' : 'AML_BROWSER_EVIDENCE_HASH_MISMATCH',
      expected,
      observed: evidence.integrity.value,
      receipt
    };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_BROWSER_EVIDENCE_VERIFY_ERROR' };
  }
}

export function exportBrowserEvidence(evidence = globalThis.__AML_EVIDENCE__) {
  if (!evidence) throw new Error('AML_BROWSER_EVIDENCE_MISSING');
  assertBrowserJSON(evidence);
  return canonicalJSONStringifyBrowser(evidence);
}

if (globalThis.document?.addEventListener) {
  document.addEventListener('aml-receipt-sealed', (event) => {
    createBrowserEvidence(event.detail).catch((error) => {
      if (globalThis.document?.dispatchEvent && globalThis.CustomEvent) {
        document.dispatchEvent(new CustomEvent('aml-evidence-error', {
          detail: { error: error?.message || 'AML_BROWSER_EVIDENCE_CREATE_ERROR' }
        }));
      }
    });
  });
}
