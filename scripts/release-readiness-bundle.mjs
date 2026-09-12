import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function runNode(script, output) {
  const run = spawnSync(process.execPath, [script, output], { encoding: 'utf8', shell: false });
  if (run.status !== 0) throw new Error(`${script} failed: ${run.stderr || run.stdout}`);
}

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-release-readiness-'));
const sbomPath = path.join(temp, 'sbom.json');
const packageManifestPath = path.join(temp, 'package-content.json');
runNode('scripts/generate-sbom.mjs', sbomPath);
runNode('scripts/package-content-manifest.mjs', packageManifestPath);

const sbomBytes = fs.readFileSync(sbomPath);
const packageManifestBytes = fs.readFileSync(packageManifestPath);
const packageManifest = JSON.parse(packageManifestBytes.toString('utf8'));

const contractPaths = [
  'project-contract.json',
  'package.json',
  'package-surface.json',
  'api-stability.json',
  'api-surface.snapshot.json',
  'cli-contract.json',
  'upgrade-contract.json',
  'security-baseline.json',
  'external-evidence.json'
];
for (const file of contractPaths) {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) throw new Error(`Required release contract missing: ${file}`);
}
const contracts = contractPaths.map(file => {
  const bytes = fs.readFileSync(file);
  return { path: file, bytes: bytes.length, sha256: sha256(bytes) };
});
const contractRootMaterial = contracts.map(item => `${item.path}\t${item.bytes}\t${item.sha256}`).join('\n') + '\n';

const bundle = {
  protocol: 'aml-release-readiness-bundle/1',
  package: pkg.name,
  version: pkg.version,
  package_content_root_sha256: packageManifest.content_root_sha256,
  package_content_file_count: packageManifest.file_count,
  sbom: {
    format: 'CycloneDX',
    spec_version: '1.5',
    sha256: sha256(sbomBytes)
  },
  contract_root_sha256: sha256(contractRootMaterial),
  contracts,
  checks: {
    package_content_manifest_generated: true,
    sbom_generated: true,
    contract_hashes_generated: true,
    complete_required_contract_set: contracts.length === contractPaths.length,
    package_identity_matches: packageManifest.package === pkg.name,
    package_version_matches: packageManifest.version === pkg.version
  },
  claim_boundary: 'Project-generated release-readiness evidence for this checkout. It does not prove npm publication, registry provenance, independent verification, certification, or production suitability.'
};
if (!Object.values(bundle.checks).every(Boolean)) throw new Error('Release readiness bundle failed identity checks');

const out = `${JSON.stringify(bundle, null, 2)}\n`;
const target = process.argv[2];
if (target) fs.writeFileSync(target, out); else process.stdout.write(out);
