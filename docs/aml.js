// ĀML browser bootstrap — SHIPPED prototype surface.
// One module activates the reference browser adoption layers.
import './aml-gate.js';
import './aml-live.js';
import './aml-page-manifest.js';

const ready = {
  schema: 'aml-browser-bootstrap/1',
  prototype: true,
  web_component: Boolean(customElements.get('aml-gate')),
  live_dom: true,
  page_manifest: true,
  receipt_global: 'window.__AML_RECEIPT__',
  receipt_history_global: 'window.__AML_RECEIPT_HISTORY__'
};

globalThis.__AML_BROWSER__ = ready;
document.dispatchEvent(new CustomEvent('aml-ready', { detail: ready }));

export default ready;
