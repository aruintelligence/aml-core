#!/usr/bin/env node

import fs from 'node:fs';
import process from 'node:process';

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const softUnavailable = process.argv.includes('--soft-unavailable');
const allowUnpublished = process.argv.includes('--allow-unpublished');
const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}`;

function repoSlug(value) {
  const text = String(value || '').trim();
  const match = text.match(/github\.com[/:]([^/]+)\/([^/#]+?)(?:\.git)?(?:[#/]|$)/i);
  return match ? `${match[1].toLowerCase()}/${match[2].replace(/\.git$/i, '').toLowerCase()}` : null;
}

const expectedSlug = repoSlug(pkg.repository?.url);

try {
  const response = await fetch(registryUrl, {
    headers: { accept: 'application/json', 'user-agent': 'aml-core-registry-identity-check/1' }
  });

  if (response.status === 404) {
    const result = {
      valid: allowUnpublished,
      status: 'unpublished_or_available',
      package: pkg.name,
      expected_repository: expectedSlug,
      registry_url: registryUrl,
      note: 'The npm registry returned 404 for this package identity. This does not prove account ownership or reserve the name.'
    };
    console.log(JSON.stringify(result, null, 2));
    process.exit(allowUnpublished ? 0 : 1);
  }

  if (!response.ok) {
    throw new Error(`npm registry returned HTTP ${response.status}`);
  }

  const metadata = await response.json();
  const latestVersion = metadata['dist-tags']?.latest || null;
  const latest = latestVersion ? metadata.versions?.[latestVersion] : null;
  const registryRepo = metadata.repository?.url || latest?.repository?.url || null;
  const actualSlug = repoSlug(registryRepo);
  const matchesCanonical = Boolean(expectedSlug && actualSlug && expectedSlug === actualSlug);

  const result = {
    valid: matchesCanonical,
    status: matchesCanonical ? 'canonical_match' : 'identity_collision_or_unverifiable_owner',
    package: pkg.name,
    registry_latest: latestVersion,
    expected_repository: expectedSlug,
    registry_repository: actualSlug,
    registry_repository_raw: registryRepo,
    registry_url: registryUrl
  };

  console.log(JSON.stringify(result, null, 2));
  process.exit(matchesCanonical ? 0 : 1);
} catch (error) {
  const result = {
    valid: softUnavailable,
    status: 'registry_unavailable',
    package: pkg.name,
    registry_url: registryUrl,
    error: error.message
  };
  console.log(JSON.stringify(result, null, 2));
  process.exit(softUnavailable ? 0 : 2);
}
