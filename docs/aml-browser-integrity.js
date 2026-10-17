// ĀML browser integrity primitives — SHIPPED reference prototype.
// SHA-256 here provides tamper evidence for exact canonical payload bytes.
// It is not a signature, endorsement, trust assertion, or proof that declared inputs are truthful.

function canonicalPrimitiveBrowser(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('AML_CANONICAL_JSON_NON_FINITE_NUMBER');
    return value;
  }
  if (['undefined', 'function', 'symbol', 'bigint'].includes(typeof value)) {
    throw new TypeError('AML_CANONICAL_JSON_UNSUPPORTED_VALUE');
  }
  return undefined;
}

export function canonicalizeBrowser(value) {
  const primitive = canonicalPrimitiveBrowser(value);
  if (primitive !== undefined || value === null) return primitive;
  if (Array.isArray(value)) return value.map(canonicalizeBrowser);
  if (value && typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('AML_CANONICAL_JSON_NON_PLAIN_OBJECT');
    }
    // Assignment to an ordinary object's "__proto__" changes its prototype
    // instead of preserving that key as signed data.
    return Object.fromEntries(
      Object.keys(value).sort().map(key => [key, canonicalizeBrowser(value[key])])
    );
  }
  throw new TypeError('AML_CANONICAL_JSON_UNSUPPORTED_VALUE');
}

export function canonicalJSONStringifyBrowser(value) {
  return JSON.stringify(canonicalizeBrowser(value));
}

// Async signing and replay must operate on the same JSON bytes from start to
// finish. A caller can otherwise mutate an object while Web Crypto yields,
// changing a verdict or returned fingerprint after its signature was checked.
export function snapshotBrowserJSON(value) {
  assertBrowserJSON(value);
  return JSON.parse(canonicalJSONStringifyBrowser(value));
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

// Sealed browser packets must be ordinary JSON data. JSON.stringify silently
// drops array properties, object symbols, and hidden keys, and turns holes into
// null; accepting those values would let a live packet change without a new hash.
export function assertBrowserJSON(value) {
  const ancestors = new Set();

  function walk(item) {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new TypeError('AML_CANONICAL_JSON_NON_FINITE_NUMBER');
      return;
    }
    if (!item || typeof item !== 'object') {
      throw new TypeError('AML_CANONICAL_JSON_UNSUPPORTED_VALUE');
    }
    if (ancestors.has(item)) throw new TypeError('AML_CANONICAL_JSON_CYCLE');
    ancestors.add(item);
    try {
      if (Array.isArray(item)) {
        if (Reflect.ownKeys(item).length !== item.length + 1) {
          throw new TypeError('AML_CANONICAL_JSON_NON_JSON_ARRAY');
        }
        for (let index = 0; index < item.length; index++) {
          const descriptor = Object.getOwnPropertyDescriptor(item, index);
          if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
            throw new TypeError('AML_CANONICAL_JSON_NON_JSON_ARRAY');
          }
          walk(descriptor.value);
        }
        return;
      }
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError('AML_CANONICAL_JSON_NON_PLAIN_OBJECT');
      }
      for (const key of Reflect.ownKeys(item)) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor)) {
          throw new TypeError('AML_CANONICAL_JSON_NON_JSON_OBJECT');
        }
        walk(descriptor.value);
      }
    } finally {
      ancestors.delete(item);
    }
  }

  walk(value);
}

export function browserReceiptPayload(receipt) {
  assertBrowserJSON(receipt);
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
    assertBrowserJSON(receipt);
    if (!receipt?.integrity || receipt.integrity.schema !== 'aml-integrity/1') {
      return { valid: false, reason: 'AML_BROWSER_RECEIPT_UNSEALED' };
    }
    if (receipt.integrity.algorithm !== 'SHA-256') {
      return { valid: false, reason: 'AML_BROWSER_RECEIPT_ALGORITHM_UNSUPPORTED' };
    }
    if (receipt.integrity.canonicalization !== 'sorted-json-v1') {
      return { valid: false, reason: 'AML_BROWSER_RECEIPT_CANONICALIZATION_UNSUPPORTED' };
    }
    if (Object.keys(receipt.integrity).sort().join('|') !== 'algorithm|canonicalization|schema|value' ||
        !/^[a-f0-9]{64}$/.test(receipt.integrity.value)) {
      return { valid: false, reason: 'AML_BROWSER_RECEIPT_INTEGRITY_INVALID' };
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
