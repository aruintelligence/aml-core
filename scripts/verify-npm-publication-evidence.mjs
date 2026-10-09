#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const digest = (algorithm, bytes) => crypto.createHash(algorithm).update(bytes).digest();

export function verifyNpmPublicationEvidence(pack, tarball, registry, expected) {
  const entry = Array.isArray(pack) ? pack[0] : pack;
  if (!entry || (Array.isArray(pack) && pack.length !== 1)) {
    throw new Error('Expected exactly one packed artifact');
  }
  if (entry.name !== expected.name || entry.version !== expected.version) {
    throw new Error('Packed package name/version differs from the stable release');
  }
  if (entry.filename !== expected.filename) throw new Error('Packed filename differs from the selected artifact');

  const sha1 = digest('sha1', tarball).toString('hex');
  const integrity = `sha512-${digest('sha512', tarball).toString('base64')}`;
  if (entry.shasum !== sha1 || entry.integrity !== integrity) {
    throw new Error('Packed metadata does not match the selected tarball bytes');
  }

  const repository = typeof registry?.repository === 'string'
    ? registry.repository : registry?.repository?.url;
  if (registry?.name !== expected.name || registry?.version !== expected.version ||
      repository !== expected.repository) {
    throw new Error('Registry identity differs from the stable release');
  }
  if (registry.dist?.shasum !== sha1 || registry.dist?.integrity !== integrity) {
    throw new Error('Registry checksums differ from the audited tarball bytes');
  }
  let tarballUrl;
  try { tarballUrl = new URL(registry.dist.tarball); } catch {
    throw new Error('Registry tarball URL is missing or invalid');
  }
  if (tarballUrl.protocol !== 'https:' || tarballUrl.hostname !== 'registry.npmjs.org' ||
      !tarballUrl.pathname.endsWith(`/${entry.filename}`)) {
    throw new Error('Registry tarball URL does not identify the expected npm artifact');
  }
  let attestationUrl;
  try { attestationUrl = new URL(registry.dist.attestations?.url); } catch {
    throw new Error('Registry provenance attestation URL is missing or invalid');
  }
  if (attestationUrl.protocol !== 'https:' || attestationUrl.hostname !== 'registry.npmjs.org' ||
      !attestationUrl.pathname.startsWith('/-/npm/v1/attestations/')) {
    throw new Error('Registry provenance attestation URL is outside npm');
  }

  return {
    protocol: 'aml-npm-registry-binding/1',
    package: expected.name,
    version: expected.version,
    repository,
    registry_version: registry.version,
    registry_integrity: registry.dist.integrity,
    registry_shasum: registry.dist.shasum,
    registry_tarball: registry.dist.tarball,
    registry_attestations_url: registry.dist.attestations.url,
    prepublish_pack_integrity: entry.integrity,
    prepublish_pack_shasum: entry.shasum,
    tarball_sha256: digest('sha256', tarball).toString('hex'),
    exact_tarball_binding_verified: true,
    claim_boundary: 'Project-generated live registry binding; not independent external verification.'
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [packPath, tarballPath, registryPath, name, version, repository] = process.argv.slice(2);
  if (![packPath, tarballPath, registryPath, name, version, repository].every(Boolean)) {
    throw new Error('usage: verify-npm-publication-evidence.mjs <pack.json> <tarball.tgz> <registry.json> <name> <version> <repository>');
  }
  const evidence = verifyNpmPublicationEvidence(
    JSON.parse(fs.readFileSync(packPath, 'utf8')),
    fs.readFileSync(tarballPath),
    JSON.parse(fs.readFileSync(registryPath, 'utf8')),
    { name, version, repository, filename: path.basename(tarballPath) }
  );
  console.log(JSON.stringify(evidence, null, 2));
}
