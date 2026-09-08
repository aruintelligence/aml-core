// ĀML browser integrity primitives — SHIPPED reference prototype.
// SHA-256 here provides tamper evidence for exact canonical payload bytes.
// It is not a signature, endorsement, trust assertion, or proof that declared inputs are truthful.

export function canonicalizeBrowser(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalizeBrowser);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) out[key] = canonicalizeBrowser(value[key]);
  }
  return out;
}

export function canonicalJSONStringifyBrowser(value) {
  return JSON.stringify(canonicalizeBrowser(value));
}

export async function sha256Browser(value) {
  if (!globalThis.crypto?.subtle) throw new Error('AML_BROWSER_CRYPTO_UNAVAILABLE');
  const bytes = new TextEncoder().encode(
    typeof value === 'string' ? value : canonicalJSONStringifyBrowser(value)
  );
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function browserReceiptPayload(receipt) {
  if (!receipt || receipt.schema !== 'aml-dom-receipt/1') {
    throw new Error('AML_BROWSER_RECEIPT_INVALID');
  }
  const { integrity, ...payload } = receipt;
  return payload;
}

export async function sealBrowserReceipt(receipt) {
  const payload = browserReceiptPayload(receipt);
  const value = await sha256Browser(payload);
  receipt.integrity = {
    schema: 'aml-integrity/1',
    algorithm: 'SHA-256',
    canonicalization: 'sorted-json-v1',
    value
  };
  return receipt;
}

export async function verifyBrowserReceipt(receipt) {
  try {
    if (!receipt?.integrity || receipt.integrity.schema !== 'aml-integrity/1') {
      return { valid: false, reason: 'AML_BROWSER_RECEIPT_UNSEALED' };
    }
    if (receipt.integrity.algorithm !== 'SHA-256') {
      return { valid: false, reason: 'AML_BROWSER_RECEIPT_ALGORITHM_UNSUPPORTED' };
    }
    const expected = await sha256Browser(browserReceiptPayload(receipt));
    const valid = expected === receipt.integrity.value;
    return {
      valid,
      reason: valid ? 'AML_BROWSER_RECEIPT_VALID' : 'AML_BROWSER_RECEIPT_HASH_MISMATCH',
      expected,
      observed: receipt.integrity.value
    };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_BROWSER_RECEIPT_VERIFY_ERROR' };
  }
}
