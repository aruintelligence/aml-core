#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const canonical = value => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
};

function usage() {
  console.error('Usage: node tools/real-screen/aml-real-screen-pilot.mjs --screen screen.html --labels labels.json [--out receipt.json]');
  process.exit(1);
}

const args = process.argv.slice(2);
const get = name => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};
const screenPath = get('--screen');
const labelsPath = get('--labels');
const outPath = get('--out');
if (!screenPath || !labelsPath) usage();

const screen = await readFile(screenPath, 'utf8');
const labelsBytes = await readFile(labelsPath, 'utf8');
const labels = JSON.parse(labelsBytes);
if (labels.protocol !== 'aml-real-screen-labels/1') throw new Error('unsupported labels protocol');
if (!Array.isArray(labels.items) || labels.items.length === 0) throw new Error('labels.items must be a non-empty array');

const markerRegex = /data-aml-id\s*=\s*["']([^"']+)["']/gi;
const markers = [...screen.matchAll(markerRegex)].map(m => m[1]);
if (!markers.length) throw new Error('screen contains no data-aml-id markers');
const uniqueMarkers = [...new Set(markers)];
if (uniqueMarkers.length !== markers.length) throw new Error('duplicate data-aml-id marker in screen');

const screenSha = sha256(screen);
if (labels.screen_sha256 !== screenSha) throw new Error(`screen_sha256 mismatch: expected ${labels.screen_sha256}, got ${screenSha}`);

const allowedKinds = new Set(['independent_review', 'operator_review', 'user_research', 'measured_proxy', 'synthetic_fixture']);
const ids = new Set();
for (const item of labels.items) {
  if (!item || typeof item !== 'object') throw new Error('label item must be an object');
  if (!item.id || !item.purpose) throw new Error('label item requires id and purpose');
  if (ids.has(item.id)) throw new Error(`duplicate label id: ${item.id}`);
  ids.add(item.id);
  for (const field of ['attention_cost', 'restoration_value']) {
    if (typeof item[field] !== 'number' || !Number.isFinite(item[field]) || item[field] < 0) throw new Error(`${item.id}.${field} must be a non-negative finite number`);
  }
  const p = item.provenance;
  if (!p || typeof p !== 'object') throw new Error(`${item.id}.provenance is required`);
  if (!allowedKinds.has(p.source_kind)) throw new Error(`${item.id}.provenance.source_kind is not allowed`);
  if (typeof p.declared_by_project !== 'boolean') throw new Error(`${item.id}.provenance.declared_by_project must be boolean`);
  if (!p.author || !p.source_reference) throw new Error(`${item.id}.provenance requires author and source_reference`);
}

for (const id of uniqueMarkers) if (!ids.has(id)) throw new Error(`screen marker has no label: ${id}`);
for (const id of ids) if (!uniqueMarkers.includes(id)) throw new Error(`label has no matching screen marker: ${id}`);

const decisions = labels.items.map(item => ({
  id: item.id,
  purpose: item.purpose,
  attention_cost: item.attention_cost,
  restoration_value: item.restoration_value,
  decision: item.restoration_value >= item.attention_cost ? 'ALLOW' : 'SUPPRESS',
  provenance: item.provenance
})).sort((a, b) => a.id.localeCompare(b.id));

const realScreenEligible = decisions.every(d => d.provenance.declared_by_project === false && d.provenance.source_kind !== 'synthetic_fixture');
const receipt = {
  protocol: 'aml-real-screen-pilot-receipt/1',
  rule: 'render_allowed = restoration_value >= attention_cost',
  screen: { sha256: screenSha, marker_count: uniqueMarkers.length },
  labels: { sha256: sha256(labelsBytes), count: decisions.length },
  decisions,
  summary: {
    allow: decisions.filter(d => d.decision === 'ALLOW').length,
    suppress: decisions.filter(d => d.decision === 'SUPPRESS').length,
    real_screen_evidence_eligible: realScreenEligible
  },
  claim_boundary: 'Deterministic policy result over declared labels. Label provenance is auditable metadata, not proof that the numeric values objectively measure human cost or benefit.'
};
receipt.receipt_root_sha256 = sha256(canonical(receipt));
const output = `${JSON.stringify(receipt, null, 2)}\n`;
if (outPath) await writeFile(outPath, output);
process.stdout.write(output);
