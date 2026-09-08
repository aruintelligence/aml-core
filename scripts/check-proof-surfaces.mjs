import fs from 'node:fs';

const required = [
  ['docs/proof.html', ['Copy this exact proof link', 'URLSearchParams', 'render_allowed = restoration_value']],
  ['docs/proof-card.html', ['ĀML Proof Card', 'compileSourceBrowser', 'Open this proof']],
  ['docs/proof-manifest.json', ['"status": "SHIPPED"', '"suppress_example"', '"allow_example"']],
  ['docs/WITNESS_KIT.md', ['Local deterministic replay', 'A negative result is useful evidence']],
  ['docs/EMBED_PROOF.md', ['<iframe', 'proof-card.html?attention=5&restoration=1']]
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
  promise: 'shareable proof + embeddable proof + witness reproduction remain present'
}, null, 2));
