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
  ['docs/gallery.html', ['ĀML Decision Gallery', 'Ten simple examples', 'Replay this state']],
  ['docs/.well-known/aml.json', ['"web_component"', '"html_bridge"', 'not an Internet standard']],
  ['docs/proof-badge.svg', ['PROOF AVAILABLE']],
  ['docs/PROOF_BADGE.md', ['does not mean official certification']],
  ['docs/worlds/ar.md', ['RTL']]
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
  promise: 'shareable proof + multilingual proof + embeddable proof + zero-install browser gates + witness reproduction remain present'
}, null, 2));
