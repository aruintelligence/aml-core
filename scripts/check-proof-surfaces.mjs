import fs from 'node:fs';

const required = [
  ['docs/proof.html', ['Copy this exact proof link', 'URLSearchParams', 'render_allowed = restoration_value', "lang === 'ar'", 'Declared purpose']],
  ['docs/proof-card.html', ['ĀML Proof Card', 'compileSourceBrowser', 'Open this proof', "lang==='ar'"]],
  ['docs/proof-manifest.json', ['"status": "SHIPPED"', '"suppress_example"', '"allow_example"']],
  ['docs/proof-links.json', ['"decision":"ALLOW"', '"decision":"SUPPRESS"']],
  ['docs/WITNESS_KIT.md', ['Local deterministic replay', 'A negative result is useful evidence']],
  ['docs/EMBED_PROOF.md', ['<iframe', 'proof-card.html?attention=5&restoration=1']],
  ['docs/aml-gate.js', ['customElements.define', 'compileSourceBrowser', 'aml-decision']],
  ['docs/AML_GATE_ELEMENT.md', ['<aml-gate>', 'SHIPPED prototype']],
  ['docs/aml-dom-gate.js', ['applyAMLDomGate', '__AML_DOM_DECISIONS__', 'compileSourceBrowser']],
  ['docs/HTML_BRIDGE.md', ['data-aml-attention-cost', 'data-aml-restoration-value']],
  ['docs/aml-live.js', ['MutationObserver', '__AML_RECEIPT__', '__AML_RECEIPT_HISTORY__', 'aml-receipt-sealed']],
  ['docs/aml-browser-integrity.js', ['SHA-256', 'verifyBrowserReceipt', 'AML_BROWSER_RECEIPT_HASH_MISMATCH', 'not a signature']],
  ['docs/aml-browser-evidence.js', ['aml-browser-evidence/1', '__AML_EVIDENCE__', 'verifyBrowserEvidence', 'zone_violations']],
  ['docs/browser-evidence-demo.html', ['ĀML Browser Evidence', 'Verify current evidence', 'Tamper with a copy and verify', 'TAMPER DETECTED']],
  ['docs/BROWSER_EVIDENCE.md', ['Browser evidence packets', 'aml-browser-evidence/1', 'SHA-256', 'does **not** prove']],
  ['docs/live-gate-demo.html', ['ĀML Live DOM Firewall', 'AI generates pressure CTA', 'aml-receipt']],
  ['docs/aml-page-manifest.js', ['application/aml+json', 'aml-page/1', 'MAX_ENTRIES = 100', 'MAX_TOTAL_MATCHES = 1000']],
  ['docs/page-manifest-demo.html', ['ĀML Page Manifest', 'application/aml+json', 'Create urgency to increase conversion']],
  ['docs/aml-zone.js', ['aml-zone-violation/1', '__AML_ZONE_VIOLATIONS__', "mode === 'strict'", 'node.hidden = true']],
  ['docs/strict-zone-demo.html', ['ĀML Strict Zone', 'Generate undeclared AI output', 'mode="strict"']],
  ['docs/aml.js', ['aml-browser-bootstrap/1', './aml-gate.js', './aml-zone.js', './aml-live.js', './aml-page-manifest.js', './aml-browser-evidence.js', '__AML_EVIDENCE__']],
  ['docs/ONE_SCRIPT_AML.md', ['One-script AML browser integration', 'window.__AML_RECEIPT__', '<aml-zone mode="strict">']],
  ['docs/one-script-demo.html', ['One script. Three AML declaration styles.', './aml.js', 'application/aml+json']],
  ['protocol/aml-page.schema.json', ['"aml-page/1"', '"maximum": 10']],
  ['protocol/aml-dom-receipt.schema.json', ['"aml-dom-receipt/1"', '"aml-integrity/1"', '"SHA-256"']],
  ['protocol/aml-browser-evidence.schema.json', ['"aml-browser-evidence/1"', '"zone_violations"', '"SHA-256"']],
  ['protocol/aml-zone-violation.schema.json', ['"aml-zone-violation/1"', '"reason"']],
  ['docs/gallery.html', ['ĀML Decision Gallery', 'Ten simple examples', 'Replay this state']],
  ['docs/.well-known/aml.json', ['"web_component"', '"html_bridge"', 'not an Internet standard']],
  ['docs/proof-badge.svg', ['PROOF AVAILABLE']],
  ['docs/PROOF_BADGE.md', ['does not mean official certification']],
  ['docs/offline-proof.html', ['ĀML Offline Proof', 'without a network connection', 'render_allowed = restoration_value']],
  ['docs/OFFLINE_PROOF.md', ['SHIPPED single-file demonstrator', 'not', 'full AML compiler']],
  ['docs/worlds/ar.md', ['<div dir="rtl">']]
];

const failures = [];
for (const [path, needles] of required) {
  if (!fs.existsSync(path)) {
    failures.push(`${path}: missing`);
    continue;
  }
  const text = fs.readFileSync(path, 'utf8');
  for (const needle of needles) {
    if (!text.includes(needle)) failures.push(`${path}: missing ${JSON.stringify(needle)}`);
  }
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  surfaces: required.map(([path]) => path),
  promise: 'shareable + multilingual + embeddable + live-DOM + page-manifest + strict-zone + browser-integrity + evidence-packet + one-script + offline AML proof surfaces remain present'
}, null, 2));
