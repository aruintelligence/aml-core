import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { verifyNpmPublicationEvidence } from '../scripts/verify-npm-publication-evidence.mjs';

const tarball = Buffer.from('fixture tarball bytes');
const sha1 = crypto.createHash('sha1').update(tarball).digest('hex');
const integrity = `sha512-${crypto.createHash('sha512').update(tarball).digest('base64')}`;
const expected = {
  name: 'aml-core', version: '1.3.0', filename: 'aml-core-1.3.0.tgz',
  repository: 'git+https://github.com/aruintelligence/aml-core.git'
};
const pack = [{ name: expected.name, version: expected.version, filename: expected.filename, shasum: sha1, integrity }];
const registry = {
  name: expected.name, version: expected.version, repository: { url: expected.repository },
  dist: {
    shasum: sha1, integrity,
    tarball: 'https://registry.npmjs.org/aml-core/-/aml-core-1.3.0.tgz',
    attestations: { url: 'https://registry.npmjs.org/-/npm/v1/attestations/aml-core@1.3.0' }
  }
};

test('binds actual registry metadata to the selected tarball bytes', () => {
  const result = verifyNpmPublicationEvidence(pack, tarball, registry, expected);
  assert.equal(result.exact_tarball_binding_verified, true);
  assert.equal(result.registry_integrity, integrity);
  assert.equal(result.registry_shasum, sha1);
  assert.equal(result.registry_attestations_url, registry.dist.attestations.url);
});

test('rejects changed tarball, forged pack checksum, and registry drift', () => {
  assert.throws(() => verifyNpmPublicationEvidence(pack, Buffer.from('changed'), registry, expected), /Packed metadata/);
  assert.throws(() => verifyNpmPublicationEvidence([{ ...pack[0], integrity: 'sha512-forged' }], tarball, registry, expected), /Packed metadata/);
  assert.throws(() => verifyNpmPublicationEvidence(pack, tarball, {
    ...registry, dist: { ...registry.dist, integrity: 'sha512-different' }
  }, expected), /Registry checksums/);
  assert.throws(() => verifyNpmPublicationEvidence(pack, tarball, {
    ...registry, repository: { url: 'git+https://github.com/other/repo.git' }
  }, expected), /Registry identity/);
  assert.throws(() => verifyNpmPublicationEvidence(pack, tarball, {
    ...registry, dist: { ...registry.dist, tarball: 'https://other.example/aml-core-1.3.0.tgz' }
  }, expected), /Registry tarball URL/);
  assert.throws(() => verifyNpmPublicationEvidence(pack, tarball, {
    ...registry, dist: { ...registry.dist, attestations: undefined }
  }, expected), /provenance attestation URL/);
  assert.throws(() => verifyNpmPublicationEvidence(pack, tarball, {
    ...registry, dist: { ...registry.dist, attestations: { url: 'https://other.example/provenance' } }
  }, expected), /outside npm/);
});
