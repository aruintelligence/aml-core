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
const artifactBindingPath = path.join(temp, 'artifact-binding.json');
runNode('scripts/generate-sbom.mjs', sbomPath);
runNode('scripts/package-content-manifest.mjs', packageManifestPath);
runNode('scripts/build-release-provenance-evidence.mjs', provenancePath);
runNode('scripts/build-artifact-provenance-binding.mjs', artifactBindingPath);

const sbomBytes = fs.readFileSync(sbomPath);
const packageManifestBytes = fs.readFileSync(packageManifestPath);
const provenanceBytes = fs.readFileSync(provenancePath);
const artifactBindingBytes = fs.readFileSync(artifactBindingPath);
const packageManifest = JSON.parse(packageManifestBytes.toString('utf8'));
const provenance = JSON.parse(provenanceBytes.toString('utf8'));
const artifactBinding = JSON.parse(artifactBindingBytes.toString('utf8'));

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
  'persisted-state-migration-vectors.json',
  'release-signing-policy.json'
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
  packed_artifact: {
    protocol: artifactBinding.protocol,
    sha256: artifactBinding.artifact.sha256,
    bytes: artifactBinding.artifact.bytes,
    npm_shasum_sha1: artifactBinding.artifact.npm_shasum_sha1,
    npm_integrity: artifactBinding.artifact.npm_integrity,
    provenance_evidence_root_sha256: artifactBinding.release_provenance.evidence_root_sha256
  },
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
    packed_artifact_bound: true,
    sbom_generated: true,
    release_provenance_generated: true,
    contract_hashes_generated: true,
    complete_required_contract_set: contracts.length === contractPaths.length,
    package_identity_matches: packageManifest.package === pkg.name && provenance.package === pkg.name && artifactBinding.package === pkg.name,
    package_version_matches: packageManifest.version === pkg.version && provenance.version === pkg.version && artifactBinding.version === pkg.version,
    rollback_commit_bound: /^[a-f0-9]{40}$/.test(provenance.rollback_target?.commit || ''),
    provenance_root_bound: /^[a-f0-9]{64}$/.test(provenance.evidence_root_sha256 || ''),
    artifact_sha256_bound: /^[a-f0-9]{64}$/.test(artifactBinding.artifact?.sha256 || ''),
    artifact_and_provenance_agree: artifactBinding.release_provenance?.evidence_root_sha256 === provenance.evidence_root_sha256
  },
  claim_boundary: 'Project-generated release-readiness evidence for this checkout. It binds rollback provenance and the npm-packed tarball bytes but does not prove npm publication, third-party attestation, independent verification, certification, or production suitability.'
};
if (!Object.values(bundle.checks).every(Boolean)) throw new Error('Release readiness bundle failed identity checks');

const out = `${JSON.stringify(bundle, null, 2)}\n`;
const target = process.argv[2];
if (target) fs.writeFileSync(target, out); else process.stdout.write(out);
