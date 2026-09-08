import { applyAMLDomGate } from './aml-dom-gate.js';

const WATCHED_ATTRIBUTES = [
  'data-aml-purpose',
  'data-aml-content',
  'data-aml-attention-cost',
  'data-aml-restoration-value'
];

let revision = 0;
let queued = false;
let observer = null;

function makeReceipt(decisions, reason) {
  revision += 1;
  const receipt = {
    schema: 'aml-dom-receipt/1',
    prototype: true,
    revision,
    reason,
    url: location.href,
    generated_at: new Date().toISOString(),
    totals: {
      evaluated: decisions.length,
      allowed: decisions.filter((row) => row.ok && row.render_allowed).length,
      suppressed: decisions.filter((row) => row.ok && !row.render_allowed).length,
      errors: decisions.filter((row) => !row.ok).length
    },
    decisions
  };

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

export function startAMLLiveGate() {
  if (observer) return observer;

  evaluateLiveAML('startup');

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
  globalThis.__AML_LIVE_OBSERVER__ = null;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => startAMLLiveGate(), { once: true });
} else {
  startAMLLiveGate();
}
