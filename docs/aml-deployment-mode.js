// Browser deployment posture shared by AML browser surfaces.
// Shadow mode records AML decisions without hiding content.
// Enforce mode applies AML decisions. Failure mode controls invalid/evaluation-error handling.

const MODES = new Set(['enforce', 'shadow']);
const FAILURE_MODES = new Set(['open', 'closed']);

function readMeta(name) {
  return document.querySelector?.(`meta[name="${name}"]`)?.getAttribute('content') || null;
}

function normalize(value, allowed, fallback) {
  return allowed.has(value) ? value : fallback;
}

export function resolveAMLDeploymentMode(element = null) {
  const attributeMode = element?.getAttribute?.('mode') || null;
  if (MODES.has(attributeMode)) return attributeMode;
  const dataMode = element?.dataset?.amlMode || null;
  if (MODES.has(dataMode)) return dataMode;
  const globalMode = globalThis.__AML_MODE__;
  if (MODES.has(globalMode)) return globalMode;
  const meta = readMeta('aml-mode');
  if (MODES.has(meta)) return meta;
  const html = document.documentElement?.dataset?.amlMode;
  return normalize(html, MODES, 'enforce');
}

export function resolveAMLFailureMode(element = null) {
  const attributeMode = element?.getAttribute?.('failure-mode') || null;
  if (FAILURE_MODES.has(attributeMode)) return attributeMode;
  const dataMode = element?.dataset?.amlFailureMode || null;
  if (FAILURE_MODES.has(dataMode)) return dataMode;
  const globalMode = globalThis.__AML_FAILURE_MODE__;
  if (FAILURE_MODES.has(globalMode)) return globalMode;
  const meta = readMeta('aml-failure-mode');
  if (FAILURE_MODES.has(meta)) return meta;
  const html = document.documentElement?.dataset?.amlFailureMode;
  // Browser bridge historically failed open on malformed declaration; preserve that default.
  return normalize(html, FAILURE_MODES, 'open');
}

export function setAMLDeploymentMode(mode) {
  if (!MODES.has(mode)) throw new Error('AML_BROWSER_INVALID_MODE');
  globalThis.__AML_MODE__ = mode;
  if (document.documentElement) document.documentElement.dataset.amlMode = mode;
  document.dispatchEvent(new CustomEvent('aml-mode-change', { detail: { mode } }));
  return mode;
}

export function setAMLFailureMode(mode) {
  if (!FAILURE_MODES.has(mode)) throw new Error('AML_BROWSER_INVALID_FAILURE_MODE');
  globalThis.__AML_FAILURE_MODE__ = mode;
  if (document.documentElement) document.documentElement.dataset.amlFailureMode = mode;
  document.dispatchEvent(new CustomEvent('aml-failure-mode-change', { detail: { failure_mode: mode } }));
  return mode;
}

export function effectiveBrowserVisibility({ amlAllowed, evaluationError = false, mode, failureMode }) {
  if (mode === 'shadow') return true;
  if (evaluationError) return failureMode === 'open';
  return Boolean(amlAllowed);
}

export const AML_BROWSER_DEPLOYMENT_MODES = Object.freeze(['enforce', 'shadow']);
export const AML_BROWSER_FAILURE_MODES = Object.freeze(['open', 'closed']);
