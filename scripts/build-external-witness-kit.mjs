import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const out = process.argv[2] || 'dist/external-witness-kit';
const files = [
  'external-witness-submission-contract.json',
  'tools/external-witness/aml-external-witness.mjs',
  'tools/external-witness/README.md'
];

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const entries = [];
for (const source of files) {
  const bytes = fs.readFileSync(source);
  const target = path.join(out, source);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, bytes);
  entries.push({ path: source, bytes: bytes.length, sha256: sha256(bytes) });
}
entries.sort((a, b) => a.path.localeCompare(b.path));
const rootBytes = Buffer.from(entries.map(e => `${e.path}\0${e.bytes}\0${e.sha256}\n`).join(''));
const manifest = {
  protocol: 'aml-external-witness-kit-manifest/1',
  purpose: 'independent PASS/FAIL/MIXED reproduction intake',
  files: entries,
  kit_root_sha256: sha256(rootBytes),
  production_private_key_included: false,
  project_attestation: false,
  claim_boundary: 'Project-built verifier tooling and intake format only. The kit does not create external independence, trust, adoption, certification, or standards status.'
};
fs.writeFileSync(path.join(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify(manifest, null, 2));
