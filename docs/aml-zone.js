import { resolveAMLDeploymentMode } from './aml-deployment-mode.js';

const DECLARED_SELECTOR = '[data-aml-attention-cost][data-aml-restoration-value]';
const SAFE_NON_UI = new Set(['SCRIPT', 'STYLE', 'TEMPLATE']);

function isDeclared(node) {
  return node.matches?.(DECLARED_SELECTOR) || node.tagName === 'AML-GATE';
}

function applyZoneVisibility(node, shouldSuppress) {
  if (shouldSuppress) {
    if (!node.hidden) {
      node.hidden = true;
      node.dataset.amlZoneHidden = 'true';
    }
    return;
  }
  if (node.dataset.amlZoneHidden === 'true') {
    node.hidden = false;
    delete node.dataset.amlZoneHidden;
  }
}

function recordViolation(zone, node, reason, deploymentMode, effectiveRendered) {
  const violation = {
    schema: 'aml-zone-violation/1',
    prototype: true,
    zone_id: zone.id || null,
    element_id: node.id || null,
    tag: node.tagName?.toLowerCase?.() || null,
    zone_mode: zone.mode,
    deployment_mode: deploymentMode,
    effective_rendered: effectiveRendered,
    reason,
    observed_at: new Date().toISOString()
  };

  globalThis.__AML_ZONE_VIOLATIONS__ ||= [];
  globalThis.__AML_ZONE_VIOLATIONS__.push(violation);
  if (globalThis.__AML_ZONE_VIOLATIONS__.length > 100) {
    globalThis.__AML_ZONE_VIOLATIONS__.shift();
  }

  zone.dispatchEvent(new CustomEvent('aml-zone-violation', {
    bubbles: true,
    detail: violation
  }));
  return violation;
}

class AMLZone extends HTMLElement {
  connectedCallback() {
    this.dataset.amlZone = this.mode;
    this._onAMLModeChange = () => this.scan('deployment-mode-change');
    document.addEventListener('aml-mode-change', this._onAMLModeChange);
    this.scan('startup');
    this.observer = new MutationObserver((mutations) => {
      if (!mutations.some((mutation) => mutation.type === 'childList' && mutation.addedNodes.length)) return;
      this.scan('dom-mutation');
    });
    this.observer.observe(this, { childList: true });
  }

  disconnectedCallback() {
    this.observer?.disconnect();
    if (this._onAMLModeChange) document.removeEventListener('aml-mode-change', this._onAMLModeChange);
  }

  get mode() {
    return this.getAttribute('mode') === 'strict' ? 'strict' : 'audit';
  }

  scan(reason = 'manual') {
    const violations = [];
    const deploymentMode = resolveAMLDeploymentMode(this);
    this.dataset.amlDeploymentMode = deploymentMode;

    for (const node of [...this.children]) {
      if (SAFE_NON_UI.has(node.tagName)) continue;
      const declared = isDeclared(node);
      node.dataset.amlDeclared = declared ? 'true' : 'false';
      if (!declared) {
        const shouldSuppress = this.mode === 'strict' && deploymentMode === 'enforce';
        const effectiveRendered = !shouldSuppress;
        applyZoneVisibility(node, shouldSuppress);
        node.dataset.amlZoneEffectiveDecision = effectiveRendered ? 'render' : 'suppress';
        const violation = recordViolation(
          this,
          node,
          `undeclared-direct-child:${reason}`,
          deploymentMode,
          effectiveRendered
        );
        violations.push(violation);
      }
    }
    return violations;
  }
}

if (!customElements.get('aml-zone')) {
  customElements.define('aml-zone', AMLZone);
}

export { AMLZone };
