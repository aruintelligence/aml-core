const results = document.getElementById('results');
const inspectButton = document.getElementById('inspect');

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

function inspectDocument() {
  const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.content ?? null;
  const receiptScript =
    document.querySelector('script[type="application/vnd.aru.aml-execution-receipt+json"]') ||
    document.querySelector('script[data-aml-receipt]');
  const authorizationScript =
    document.querySelector('script[type="application/vnd.aru.aml-brand-authorization+json"]') ||
    document.querySelector('script[data-aml-brand-authorization]');

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

  return {
    url: location.href,
    title: document.title,
    profile: meta('aml-profile') || receipt?.profile?.id || null,
    policy: meta('aml-policy') || receipt?.selected_render?.policy_id || null,
    receipt_sha256: meta('aml-receipt-sha256') || receipt?.receipt_sha256 || null,
    allowed: typeof receipt?.selected_render?.suppressed === 'number'
      ? receipt.selected_render.suppressed === 0
      : null,
    receipt_present: Boolean(receiptScript),
    receipt_parseable: Boolean(receipt),
    receipt_error: receiptError,
    authorization_present: Boolean(authorizationScript),
    authorization_parseable: Boolean(authorization),
    authorization_credential_hash: authorization?.credential_hash ?? null,
    authorization_grantee: authorization?.grantee?.name ?? authorization?.grantee ?? null,
    authorization_error: authorizationError
  };
}

async function inspectActiveTab() {
  results.innerHTML = card('Status', 'Inspecting…', 'muted');
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error('No active tab available.');
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: inspectDocument
    });

    const blocks = [];
    blocks.push(card('Page', result.title || result.url));
    blocks.push(card('AML receipt', result.receipt_present ? (result.receipt_parseable ? 'Declared receipt found' : 'Receipt metadata found but JSON is invalid') : 'No embedded AML receipt found', result.receipt_parseable ? 'ok' : 'warn'));
    if (result.receipt_sha256) blocks.push(card('Receipt SHA-256', result.receipt_sha256));
    if (result.profile) blocks.push(card('Profile', result.profile));
    if (result.policy) blocks.push(card('Policy', result.policy));
    if (result.allowed !== null) blocks.push(card('Declared render result', result.allowed ? 'Allowed' : 'Contains suppressed output', result.allowed ? 'ok' : 'warn'));
    blocks.push(card('Official authorization metadata', result.authorization_present ? (result.authorization_parseable ? 'Credential metadata found — verify separately' : 'Authorization metadata is invalid JSON') : 'No embedded authorization credential found', result.authorization_parseable ? 'warn' : 'muted'));
    if (result.authorization_grantee) blocks.push(card('Authorization grantee', result.authorization_grantee));
    if (result.authorization_credential_hash) blocks.push(card('Authorization credential hash', result.authorization_credential_hash));
    if (result.receipt_error) blocks.push(card('Receipt parse error', result.receipt_error, 'warn'));
    if (result.authorization_error) blocks.push(card('Authorization parse error', result.authorization_error, 'warn'));
    blocks.push(card('Privacy', 'Inspection stayed local to this extension invocation. No page content was uploaded.'));
    results.innerHTML = blocks.join('');
  } catch (error) {
    results.innerHTML = card('Inspection failed', error.message || 'Unable to inspect this page.', 'warn');
  }
}

inspectButton.addEventListener('click', inspectActiveTab);
