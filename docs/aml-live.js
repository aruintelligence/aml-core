import { applyAMLDomGate } from './aml-dom-gate.js';
import { sealBrowserReceipt } from './aml-browser-integrity.js';
import { resolveAMLDeploymentMode, resolveAMLFailureMode } from './aml-deployment-mode.js';

const WATCHED_ATTRIBUTES = [
  'data-aml-purpose',
  'data-aml-content',
  'data-aml-attention-cost',
  'data-aml-restoration-value'
];

let revision = 0;
let queued = false;
let observer = null;

function publishReceipt(receipt) {
  globalThis.__AML_RECEIPT__ = receipt;
  globalThis.__AML_RECEIPT_HISTORY__ ||= [];
  globalThis.__AML_RECEIPT_HISTORY__.push(receipt);
  if (globalThis.__AML_RECEIPT_HISTORY__.length > 50) {
    globalThis.__AML_RECEIPT_HISTORY__.shift();
  }

  document.dispatchEvent(new CustomEvent('aml-receipt', {
    bubbles: false,
    detail: receipt
  }));
}

function sealReceipt(receipt) {
  sealBrowserReceipt(receipt)
    .then((sealed) => {
      document.dispatchEvent(new CustomEvent('aml-receipt-sealed', {
        bubbles: false,
        detail: sealed
      }));
    })
    .catch((error) => {
      receipt.integrity_error = error?.message || 'AML_BROWSER_RECEIPT_SEAL_ERROR';
      document.dispatchEvent(new CustomEvent('aml-receipt-seal-error', {
        bubbles: false,
        detail: { receipt, error: receipt.integrity_error }
      }));
    });
}

function countBy(decisions, field) {
  return decisions.reduce((acc, row) => {
    const key = row[field] ?? 'unknown';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function makeReceipt(decisions, reason) {
  revision += 1;
  const receipt = {
    schema: 'aml-dom-receipt/1',
    prototype: true,
    revision,
    reason,
    url: location.href,
    generated_at: new Date().toISOString(),
    deployment: {
      default_mode: resolveAMLDeploymentMode(),
      default_failure_mode: resolveAMLFailureMode(),
      mode_counts: countBy(decisions, 'deployment_mode'),
      failure_mode_counts: countBy(decisions, 'failure_mode')
    },
    totals: {
      evaluated: decisions.length,
      allowed: decisions.filter((row) => row.ok && row.render_allowed).length,
      suppressed: decisions.filter((row) => row.ok && !row.render_allowed).length,
      errors: decisions.filter((row) => !row.ok).length,
      effective_rendered: decisions.filter((row) => row.effective_rendered === true).length,
      effective_suppressed: decisions.filter((row) => row.effective_rendered === false).length,
      shadowed_suppressions: decisions.filter((row) => row.render_allowed === false && row.effective_rendered === true).length
    },
    decisions
  };

  publishReceipt(receipt);
  sealReceipt(receipt);
  return receipt;
}

export function evaluateLiveAML(reason = 'manual') {
  const decisions = applyAMLDomGate(document);
  return makeReceipt(decisions, reason);
}

function queueEvaluation(reason) {
  if (queued) return;
  queued = true;
  queueMicrotask(() => {
    queued = false;
    evaluateLiveAML(reason);
  });
}

function onModeChange() {
  queueEvaluation('deployment-mode-change');
}

function onFailureModeChange() {
  queueEvaluation('failure-mode-change');
}

export function startAMLLiveGate() {
  if (observer) return observer;

  evaluateLiveAML('startup');
  document.addEventListener('aml-mode-change', onModeChange);
  document.addEventListener('aml-failure-mode-change', onFailureModeChange);

  observer = new MutationObserver((mutations) => {
    const relevant = mutations.some((mutation) => {
      if (mutation.type === 'childList') {
        return [...mutation.addedNodes].some((node) =>
          node.nodeType === Node.ELEMENT_NODE && (
            node.matches?.('[data-aml-attention-cost][data-aml-restoration-value]') ||
            node.querySelector?.('[data-aml-attention-cost][data-aml-restoration-value]')
          )
        );
      }
      return mutation.type === 'attributes' && WATCHED_ATTRIBUTES.includes(mutation.attributeName);
    });

    if (relevant) queueEvaluation('dom-mutation');
  });

  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: WATCHED_ATTRIBUTES
  });

  globalThis.__AML_LIVE_OBSERVER__ = observer;
  return observer;
}

export function stopAMLLiveGate() {
  observer?.disconnect();
  observer = null;
  document.removeEventListener('aml-mode-change', onModeChange);
  document.removeEventListener('aml-failure-mode-change', onFailureModeChange);
  globalThis.__AML_LIVE_OBSERVER__ = null;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => startAMLLiveGate(), { once: true });
} else {
  startAMLLiveGate();
}
