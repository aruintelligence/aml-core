const DECLARED_SELECTOR = '[data-aml-attention-cost][data-aml-restoration-value]';
const SAFE_NON_UI = new Set(['SCRIPT', 'STYLE', 'TEMPLATE']);

function isDeclared(node) {
  return node.matches?.(DECLARED_SELECTOR) || node.tagName === 'AML-GATE';
}

function recordViolation(zone, node, reason) {
  const violation = {
    schema: 'aml-zone-violation/1',
    prototype: true,
    zone_id: zone.id || null,
    element_id: node.id || null,
    tag: node.tagName?.toLowerCase?.() || null,
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
    this.scan('startup');
    this.observer = new MutationObserver((mutations) => {
      if (!mutations.some((mutation) => mutation.type === 'childList' && mutation.addedNodes.length)) return;
      this.scan('dom-mutation');
    });
    this.observer.observe(this, { childList: true });
  }

  disconnectedCallback() {
    this.observer?.disconnect();
  }

  get mode() {
    return this.getAttribute('mode') === 'strict' ? 'strict' : 'audit';
  }

  scan(reason = 'manual') {
    const violations = [];
    for (const node of [...this.children]) {
      if (SAFE_NON_UI.has(node.tagName)) continue;
      const declared = isDeclared(node);
      node.dataset.amlDeclared = declared ? 'true' : 'false';
      if (!declared) {
        const violation = recordViolation(this, node, `undeclared-direct-child:${reason}`);
        violations.push(violation);
        if (this.mode === 'strict') node.hidden = true;
      }
    }
    return violations;
  }
}

if (!customElements.get('aml-zone')) {
  customElements.define('aml-zone', AMLZone);
}

export { AMLZone };
