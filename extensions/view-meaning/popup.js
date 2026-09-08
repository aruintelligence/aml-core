const results = document.getElementById('results');
const inspectButton = document.getElementById('inspect');
const TRUST_URL = 'https://raw.githubusercontent.com/aruintelligence/aml-core/main/BRAND_TRUST_ROOTS.json';

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function card(label, value, className = '') {
  return `<div class="card"><div class="label">${escapeHtml(label)}</div><div class="value ${className}">${escapeHtml(value)}</div></div>`;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function canonicalJSONStringify(value) {
  return JSON.stringify(canonicalize(value));
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256Text(value) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

function b64Bytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function pemDer(pem) {
  return b64Bytes(pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/\s+/g, ''));
}

async function verifyReceipt(receipt) {
  if (!receipt || receipt.protocol !== 'ĀML Accountable Execution Receipt') {
    return { valid: false, reason: 'invalid_receipt_type' };
  }
  const { receipt_sha256, signature, ...payload } = receipt;
  const expected = await sha256Text(stableStringify(payload));
  return {
    valid: expected === receipt_sha256,
    reason: expected === receipt_sha256 ? null : 'receipt_hash_mismatch',
    expected,
    actual: receipt_sha256 ?? null
  };
}

async function verifyBrandCredential(credential, trustRegistry) {
  if (!credential || credential.type !== 'aml-brand-authorization/1') {
    return { valid: false, official: false, reason: 'invalid_type' };
  }

  const { credential_hash, algorithm, public_key_pem, public_key_sha256, signature_base64, ...body } = credential;
  if (algorithm !== 'Ed25519') return { valid: false, official: false, reason: 'unsupported_algorithm' };
  if (credential.expires_at && Date.now() >= new Date(credential.expires_at).getTime()) {
    return { valid: false, official: false, reason: 'expired' };
  }

  const canonical = canonicalJSONStringify(body);
  if (await sha256Text(canonical) !== credential_hash) {
    return { valid: false, official: false, reason: 'credential_hash_mismatch' };
  }

  try {
    const der = pemDer(public_key_pem);
    const fingerprint = hex(await crypto.subtle.digest('SHA-256', der));
    if (fingerprint !== public_key_sha256) {
      return { valid: false, official: false, reason: 'public_key_fingerprint_mismatch' };
    }
    const key = await crypto.subtle.importKey('spki', der, { name: 'Ed25519' }, false, ['verify']);
    const signatureValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      b64Bytes(signature_base64),
      new TextEncoder().encode(canonical)
    );
    if (!signatureValid) return { valid: false, official: false, reason: 'signature_invalid' };
  } catch (error) {
    return { valid: false, official: false, reason: 'invalid_key_or_signature', detail: error.message };
  }

  if (!trustRegistry || trustRegistry.type !== 'aml-brand-trust-roots/1') {
    return { valid: true, official: false, reason: 'trust_registry_unavailable_or_invalid' };
  }
  if (credential.issuer !== (trustRegistry.owner || 'ĀRU Intelligence Inc.')) {
    return { valid: true, official: false, reason: 'issuer_mismatch' };
  }
  if ((trustRegistry.revoked_keys || []).some((entry) => entry.public_key_sha256 === public_key_sha256)) {
    return { valid: true, official: false, reason: 'signing_key_revoked' };
  }
  const trusted = (trustRegistry.active_keys || []).find((entry) => entry.public_key_sha256 === public_key_sha256) || null;
  if (!trusted) return { valid: true, official: false, reason: 'untrusted_signing_key' };
  return { valid: true, official: true, reason: null, trust_root: trusted };
}

function inspectDocument() {
  const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.content ?? null;
  const receiptScript = document.querySelector('script[type="application/vnd.aru.aml-execution-receipt+json"]') || document.querySelector('script[data-aml-receipt]');
  const authorizationScript = document.querySelector('script[type="application/vnd.aru.aml-brand-authorization+json"]') || document.querySelector('script[data-aml-brand-authorization]');

  let receipt = null;
  let receiptError = null;
  if (receiptScript?.textContent?.trim()) {
    try { receipt = JSON.parse(receiptScript.textContent); }
    catch (error) { receiptError = error.message; }
  }

  let authorization = null;
  let authorizationError = null;
  if (authorizationScript?.textContent?.trim()) {
    try { authorization = JSON.parse(authorizationScript.textContent); }
    catch (error) { authorizationError = error.message; }
  }

  const purposes = (receipt?.intent?.nodes || [])
    .map((node) => node?.properties?.purpose)
    .filter(Boolean);

  return {
    url: location.href,
    title: document.title,
    profile: meta('aml-profile') || receipt?.profile?.id || null,
    policy: meta('aml-policy') || receipt?.selected_render?.policy_id || null,
    purposes,
    context: receipt?.context || null,
    receipt_sha256: meta('aml-receipt-sha256') || receipt?.receipt_sha256 || null,
    allowed: typeof receipt?.selected_render?.suppressed === 'number' ? receipt.selected_render.suppressed === 0 : null,
    receipt,
    receipt_present: Boolean(receiptScript),
    receipt_parseable: Boolean(receipt),
    receipt_error: receiptError,
    authorization,
    authorization_present: Boolean(authorizationScript),
    authorization_parseable: Boolean(authorization),
    authorization_error: authorizationError
  };
}

async function loadTrustRegistry() {
  try {
    const response = await fetch(TRUST_URL, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch {
    return null;
  }
}

function formatContext(context) {
  if (!context || typeof context !== 'object') return 'No runtime context declared';
  const interesting = [
    ['consent_granted', context.consent_granted],
    ['privacy_consent', context.privacy_consent],
    ['prefers_reduced_motion', context.prefers_reduced_motion],
    ['high_contrast_required', context.high_contrast_required],
    ['max_cognitive_load', context.max_cognitive_load],
    ['attention_budget_remaining', context.attention_budget_remaining]
  ].filter(([, value]) => value !== undefined);
  return interesting.length ? interesting.map(([key, value]) => `${key}=${String(value)}`).join(' · ') : 'Runtime context present; no standard consent/privacy/accessibility flags declared';
}

async function inspectActiveTab() {
  results.innerHTML = card('Status', 'Inspecting…', 'muted');
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error('No active tab available.');
    const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: inspectDocument });

    const [receiptVerification, trustRegistry] = await Promise.all([
      result.receipt ? verifyReceipt(result.receipt) : Promise.resolve(null),
      result.authorization ? loadTrustRegistry() : Promise.resolve(null)
    ]);
    const authorizationVerification = result.authorization ? await verifyBrandCredential(result.authorization, trustRegistry) : null;

    const blocks = [card('Page', result.title || result.url)];
    blocks.push(card(
      'AML receipt integrity',
      !result.receipt_present ? 'No embedded AML receipt found' :
      !result.receipt_parseable ? 'Receipt JSON is invalid' :
      receiptVerification?.valid ? 'VALID — receipt hash recomputed locally' : `INVALID — ${receiptVerification?.reason || 'verification failed'}`,
      receiptVerification?.valid ? 'ok' : 'warn'
    ));
    if (result.purposes?.length) blocks.push(card('Declared purpose', result.purposes.join(' | ')));
    if (result.profile) blocks.push(card('Profile', result.profile));
    if (result.policy) blocks.push(card('Policy', result.policy));
    if (result.context) blocks.push(card('Consent / privacy / accessibility context', formatContext(result.context)));
    if (result.receipt_sha256) blocks.push(card('Receipt SHA-256', result.receipt_sha256));
    if (result.allowed !== null) blocks.push(card('Render result', result.allowed ? 'Allowed' : 'Contains suppressed output', result.allowed ? 'ok' : 'warn'));

    blocks.push(card(
      'Official AML authorization',
      !result.authorization_present ? 'No embedded authorization credential found' :
      !result.authorization_parseable ? 'Authorization JSON is invalid' :
      authorizationVerification?.official ? 'OFFICIAL — valid credential signed by an active ĀRU trust root' :
      authorizationVerification?.valid ? `Cryptographically valid, NOT OFFICIAL — ${authorizationVerification.reason}` :
      `INVALID — ${authorizationVerification?.reason || 'verification failed'}`,
      authorizationVerification?.official ? 'ok' : 'warn'
    ));

    if (result.authorization?.grantee) blocks.push(card('Authorization grantee', result.authorization.grantee?.name ?? result.authorization.grantee));
    if (result.authorization?.credential_hash) blocks.push(card('Authorization credential hash', result.authorization.credential_hash));
    if (trustRegistry) blocks.push(card('ĀRU trust registry', `${trustRegistry.status || 'unknown'} · ${(trustRegistry.active_keys || []).length} active key(s)`));
    if (result.receipt_error) blocks.push(card('Receipt parse error', result.receipt_error, 'warn'));
    if (result.authorization_error) blocks.push(card('Authorization parse error', result.authorization_error, 'warn'));
    blocks.push(card('Privacy', 'Verification occurred locally. The extension fetched only the public ĀRU trust-root registry when an authorization credential was present; page content and credentials were not uploaded.'));
    results.innerHTML = blocks.join('');
  } catch (error) {
    results.innerHTML = card('Inspection failed', error.message || 'Unable to inspect this page.', 'warn');
  }
}

inspectButton.addEventListener('click', inspectActiveTab);
