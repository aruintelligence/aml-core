import { compileSourceBrowser } from './aml-browser.js';
import {
  effectiveBrowserVisibility,
  resolveAMLDeploymentMode,
  resolveAMLFailureMode
} from './aml-deployment-mode.js';

function quoted(value) {
  return JSON.stringify(String(value ?? ''));
}

export class AMLGateElement extends HTMLElement {
  static get observedAttributes() {
    return ['purpose', 'attention-cost', 'restoration-value', 'content', 'mode', 'failure-mode'];
  }

  connectedCallback() {
    this.evaluate();
  }

  attributeChangedCallback() {
    if (this.isConnected) this.evaluate();
  }

  evaluate() {
    const attention = Number(this.getAttribute('attention-cost') ?? 0);
    const restoration = Number(this.getAttribute('restoration-value') ?? 0);
    const purpose = this.getAttribute('purpose') || 'Undeclared interface purpose';
    const content = this.getAttribute('content') || this.textContent.trim().slice(0, 200) || 'Interface element';
    const deploymentMode = resolveAMLDeploymentMode(this);
    const failureMode = resolveAMLFailureMode(this);

    if (!Number.isFinite(attention) || !Number.isFinite(restoration)) {
      const effectiveRendered = effectiveBrowserVisibility({
        amlAllowed: null,
        evaluationError: true,
        mode: deploymentMode,
        failureMode
      });
      this.dataset.amlDecision = 'error';
      this.dataset.amlMode = deploymentMode;
      this.dataset.amlFailureMode = failureMode;
      this.dataset.amlEffectiveDecision = effectiveRendered ? 'render' : 'suppress';
      this.hidden = !effectiveRendered;
      const detail = {
        ok: false,
        deployment_mode: deploymentMode,
        failure_mode: failureMode,
        render_allowed: null,
        effective_rendered: effectiveRendered,
        error: 'attention-cost and restoration-value must be finite numbers'
      };
      this.amlDecision = detail;
      this.dispatchEvent(new CustomEvent('aml-decision', { bubbles: true, detail }));
      return;
    }

    const source = `transmission "web_component" {\n  message "wrapped_element" {\n    purpose: ${quoted(purpose)}\n    content: ${quoted(content)}\n    attention_cost: ${attention}\n    restoration_value: ${restoration}\n  }\n}\n`;

    const result = compileSourceBrowser(source);
    const decision = result.renderDecisions[0];
    const allowed = Boolean(decision.render_allowed);
    const effectiveRendered = effectiveBrowserVisibility({
      amlAllowed: allowed,
      evaluationError: false,
      mode: deploymentMode,
      failureMode
    });

    this.dataset.amlDecision = allowed ? 'allow' : 'suppress';
    this.dataset.amlMode = deploymentMode;
    this.dataset.amlFailureMode = failureMode;
    this.dataset.amlEffectiveDecision = effectiveRendered ? 'render' : 'suppress';
    this.hidden = !effectiveRendered;

    const detail = {
      ok: true,
      purpose,
      attention_cost: decision.attention_cost,
      restoration_value: decision.restoration_value,
      render_allowed: allowed,
      effective_rendered: effectiveRendered,
      deployment_mode: deploymentMode,
      failure_mode: failureMode,
      would_suppress: !allowed,
      source
    };

    this.amlDecision = detail;
    this.dispatchEvent(new CustomEvent('aml-decision', { bubbles: true, detail }));
  }
}

if (!customElements.get('aml-gate')) {
  customElements.define('aml-gate', AMLGateElement);
}
