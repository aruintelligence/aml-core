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
const provenancePath = path.join(temp, 'release-provenance.json');
runNode('scripts/generate-sbom.mjs', sbomPath);
runNode('scripts/package-content-manifest.mjs', packageManifestPath);
runNode('scripts/build-release-provenance-evidence.mjs', provenancePath);

const sbomBytes = fs.readFileSync(sbomPath);
const packageManifestBytes = fs.readFileSync(packageManifestPath);
const provenanceBytes = fs.readFileSync(provenancePath);
const packageManifest = JSON.parse(packageManifestBytes.toString('utf8'));
const provenance = JSON.parse(provenanceBytes.toString('utf8'));

const contractPaths = [
  'project-contract.json',
  'package.json',
  'package-surface.json',
  'api-stability.json',
  'api-surface.snapshot.json',
  'cli-contract.json',
  'upgrade-contract.json',
  'security-baseline.json',
  'external-evidence.json',
  'release-channels.json',
  'rollback-contract.json',
  'support-policy.json',
  'protocol-compatibility.json',
  'persisted-state-contract.json',
  'persisted-state-migration-vectors.json'
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
  release_provenance: {
    protocol: provenance.protocol,
    sha256: sha256(provenanceBytes),
    evidence_root_sha256: provenance.evidence_root_sha256,
    control_commit: provenance.control_commit,
    rollback_target: provenance.rollback_target
  },
  contract_root_sha256: sha256(contractRootMaterial),
  contracts,
  checks: {
    package_content_manifest_generated: true,
    sbom_generated: true,
    release_provenance_generated: true,
    contract_hashes_generated: true,
    complete_required_contract_set: contracts.length === contractPaths.length,
    package_identity_matches: packageManifest.package === pkg.name && provenance.package === pkg.name,
    package_version_matches: packageManifest.version === pkg.version && provenance.version === pkg.version,
    rollback_commit_bound: /^[a-f0-9]{40}$/.test(provenance.rollback_target?.commit || ''),
    provenance_root_bound: /^[a-f0-9]{64}$/.test(provenance.evidence_root_sha256 || '')
  },
  claim_boundary: 'Project-generated release-readiness evidence for this checkout. It binds rollback provenance but does not prove npm publication, third-party attestation, independent verification, certification, or production suitability.'
};
if (!Object.values(bundle.checks).every(Boolean)) throw new Error('Release readiness bundle failed identity checks');

const out = `${JSON.stringify(bundle, null, 2)}\n`;
const target = process.argv[2];
if (target) fs.writeFileSync(target, out); else process.stdout.write(out);
