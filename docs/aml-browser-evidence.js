import { canonicalJSONStringifyBrowser, sha256Browser, verifyBrowserReceipt } from './aml-browser-integrity.js';

let evidenceRevision = 0;

function currentViolations() {
  return [...(globalThis.__AML_ZONE_VIOLATIONS__ || [])];
}

export function browserEvidencePayload(evidence) {
  if (!evidence || evidence.schema !== 'aml-browser-evidence/1') {
    throw new Error('AML_BROWSER_EVIDENCE_INVALID');
  }
  const { integrity, ...payload } = evidence;
  return payload;
}

export async function createBrowserEvidence(receipt = globalThis.__AML_RECEIPT__) {
  if (!receipt?.integrity) throw new Error('AML_BROWSER_EVIDENCE_REQUIRES_SEALED_RECEIPT');
  const receiptCheck = await verifyBrowserReceipt(receipt);
  if (!receiptCheck.valid) throw new Error('AML_BROWSER_EVIDENCE_RECEIPT_INVALID');

  evidenceRevision += 1;
  const evidence = {
    schema: 'aml-browser-evidence/1',
    prototype: true,
    revision: evidenceRevision,
    url: location.href,
    generated_at: new Date().toISOString(),
    receipt,
    zone_violations: currentViolations()
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

  document.dispatchEvent(new CustomEvent('aml-evidence', {
    bubbles: false,
    detail: evidence
  }));
  return evidence;
}

export async function verifyBrowserEvidence(evidence) {
  try {
    if (!evidence?.integrity || evidence.integrity.schema !== 'aml-integrity/1') {
      return { valid: false, reason: 'AML_BROWSER_EVIDENCE_UNSEALED' };
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
  return canonicalJSONStringifyBrowser(evidence);
}

document.addEventListener('aml-receipt-sealed', (event) => {
  createBrowserEvidence(event.detail).catch((error) => {
    document.dispatchEvent(new CustomEvent('aml-evidence-error', {
      detail: { error: error?.message || 'AML_BROWSER_EVIDENCE_CREATE_ERROR' }
    }));
  });
});
