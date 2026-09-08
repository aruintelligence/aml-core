import { compileSourceBrowser } from './aml-browser.js';

function quoted(value) {
  return JSON.stringify(String(value ?? ''));
}

export class AMLGateElement extends HTMLElement {
  static get observedAttributes() {
    return ['purpose', 'attention-cost', 'restoration-value', 'content'];
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

    if (!Number.isFinite(attention) || !Number.isFinite(restoration)) {
      this.dataset.amlDecision = 'error';
      this.hidden = false;
      this.dispatchEvent(new CustomEvent('aml-decision', {
        bubbles: true,
        detail: { ok: false, error: 'attention-cost and restoration-value must be finite numbers' }
      }));
      return;
    }

    const source = `transmission "web_component" {\n  message "wrapped_element" {\n    purpose: ${quoted(purpose)}\n    content: ${quoted(content)}\n    attention_cost: ${attention}\n    restoration_value: ${restoration}\n  }\n}\n`;

    const result = compileSourceBrowser(source);
    const decision = result.renderDecisions[0];
    const allowed = Boolean(decision.render_allowed);

    this.dataset.amlDecision = allowed ? 'allow' : 'suppress';
    this.hidden = !allowed;

    const detail = {
      ok: true,
      purpose,
      attention_cost: decision.attention_cost,
      restoration_value: decision.restoration_value,
      render_allowed: allowed,
      source
    };

    this.amlDecision = detail;
    this.dispatchEvent(new CustomEvent('aml-decision', { bubbles: true, detail }));
  }
}

if (!customElements.get('aml-gate')) {
  customElements.define('aml-gate', AMLGateElement);
}
