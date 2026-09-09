import { compileSourceBrowser } from './aml-browser.js';
import {
  effectiveBrowserVisibility,
  resolveAMLDeploymentMode,
  resolveAMLFailureMode
} from './aml-deployment-mode.js';

function quoted(value) {
  return JSON.stringify(String(value ?? ''));
}

function evaluateElement(element, index) {
  const attention = Number(element.dataset.amlAttentionCost ?? 0);
  const restoration = Number(element.dataset.amlRestorationValue ?? 0);
  const purpose = element.dataset.amlPurpose || 'Undeclared interface purpose';
  const content = (element.dataset.amlContent || element.textContent || 'Interface element').trim().slice(0, 200);
  const deploymentMode = resolveAMLDeploymentMode(element);
  const failureMode = resolveAMLFailureMode(element);

  if (!Number.isFinite(attention) || !Number.isFinite(restoration)) {
    const effectiveRendered = effectiveBrowserVisibility({
      amlAllowed: null,
      evaluationError: true,
      mode: deploymentMode,
      failureMode
    });
    element.dataset.amlDecision = 'error';
    element.dataset.amlMode = deploymentMode;
    element.dataset.amlFailureMode = failureMode;
    element.dataset.amlEffectiveDecision = effectiveRendered ? 'render' : 'suppress';
    element.hidden = !effectiveRendered;
    return {
      ok: false,
      index,
      id: element.id || null,
      deployment_mode: deploymentMode,
      failure_mode: failureMode,
      render_allowed: null,
      effective_rendered: effectiveRendered,
      error: 'AML_DOM_INVALID_SCORE'
    };
  }

  const source = `transmission "dom_bridge" {\n  message "element_${index}" {\n    purpose: ${quoted(purpose)}\n    content: ${quoted(content)}\n    attention_cost: ${attention}\n    restoration_value: ${restoration}\n  }\n}\n`;

  const compiled = compileSourceBrowser(source);
  const decision = compiled.renderDecisions[0];
  const allowed = Boolean(decision.render_allowed);
  const effectiveRendered = effectiveBrowserVisibility({
    amlAllowed: allowed,
    evaluationError: false,
    mode: deploymentMode,
    failureMode
  });

  element.dataset.amlDecision = allowed ? 'allow' : 'suppress';
  element.dataset.amlMode = deploymentMode;
  element.dataset.amlFailureMode = failureMode;
  element.dataset.amlEffectiveDecision = effectiveRendered ? 'render' : 'suppress';
  element.hidden = !effectiveRendered;

  return {
    ok: true,
    index,
    id: element.id || null,
    purpose,
    attention_cost: decision.attention_cost,
    restoration_value: decision.restoration_value,
    render_allowed: allowed,
    effective_rendered: effectiveRendered,
    deployment_mode: deploymentMode,
    failure_mode: failureMode,
    would_suppress: !allowed
  };
}

export function applyAMLDomGate(root = document) {
  const selector = '[data-aml-attention-cost][data-aml-restoration-value]';
  const nodes = [...root.querySelectorAll(selector)];
  const decisions = nodes.map((node, index) => evaluateElement(node, index));

  globalThis.__AML_DOM_DECISIONS__ = decisions;
  root.dispatchEvent?.(new CustomEvent('aml-dom-gated', {
    bubbles: false,
    detail: { count: decisions.length, decisions }
  }));

  return decisions;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => applyAMLDomGate());
} else {
  applyAMLDomGate();
}
