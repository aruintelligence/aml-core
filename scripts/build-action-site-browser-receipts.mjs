#!/usr/bin/env node
// Recompute paired live-browser receipts from public source checkpoints,
// screenshots and serialized DOM. No browser or network needed for verification.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const evidenceDirArg = process.argv.indexOf('--evidence-dir');
const evidenceDir = evidenceDirArg >= 0 ? path.resolve(process.argv[evidenceDirArg + 1]) :
  path.join(root, 'docs/action-pilots/evidence');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'pilots/action-boundary/controlled-sites.json')));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hash = value => sha(canonicalJSONStringify(value));
const beforeCommit = '877a8f8d64adf2d44c27dda73f1efe9f88d60418';
const afterCommit = 'bb64ada9071307be762a295b6c482439a5bff21b';
const sourcePath = (stage, name) => `docs/action-pilots/${stage}/${name}.html`;
const sourceAt = (commit, file) => execFileSync('git', ['show', `${commit}:${file}`],
  { cwd: root, maxBuffer: 1024 * 1024 });

function state(site, stage) {
  const name = `${site.id}-${site.slug}`;
  const prefix = `pilot-${name}-${stage}`;
  const record = JSON.parse(fs.readFileSync(path.join(evidenceDir, `${prefix}.json`), 'utf8'));
  const dom = fs.readFileSync(path.join(evidenceDir, `${prefix}.dom.html`));
  const screenshot = fs.readFileSync(path.join(evidenceDir, `${prefix}.jpg`));
  assert.equal(record.protocol, 'aml-controlled-site-browser-state/1');
  assert.equal(record.pilot_id, site.id);
  assert.equal(record.stage, stage);
  assert.equal(record.source_commit, stage === 'before' ? beforeCommit : afterCommit);
  assert.equal(record.url, `https://aruintelligence.github.io/aml-core/action-pilots/${stage}/${name}.html`);
  assert.equal(record.dom_file, `${prefix}.dom.html`);
  assert.equal(record.screenshot_file, `${prefix}.jpg`);
  assert.equal(record.dom_sha256, sha(dom));
  assert.equal(record.screenshot_sha256, sha(screenshot));
  assert.equal(record.target_selector, '#redundant-contact');
  assert.equal(record.contact_selector, '#contact-action');
  assert.equal(record.contact_count, 1);
  assert.ok(record.contact_outer_html.includes(`href="${manifest.contact_href}"`));
  assert.ok(dom.toString('utf8').includes(record.contact_outer_html));
  assert.equal(record.target_count, stage === 'before' ? 1 : 0);
  if (stage === 'before') {
    assert.ok(record.target_outer_html.includes(`href="${manifest.contact_href}"`));
    assert.ok(dom.toString('utf8').includes(record.target_outer_html));
  } else assert.equal(record.target_outer_html, null);
  const rel = sourcePath(stage, name);
  const currentSource = fs.readFileSync(path.join(root, rel));
  assert.equal(sha(currentSource), sha(sourceAt(record.source_commit, rel)));
  return { record, dom: dom.toString('utf8'), source: currentSource };
}

function withoutDuplicate(dom) {
  const pattern = /\n    <aside id="redundant-contact"[\s\S]*?<\/aside>/g;
  assert.equal([...dom.matchAll(pattern)].length, 1, 'exactly one target must be removed');
  return dom.replace(pattern, '');
}

const mode = process.argv[2];
if (!['--write', '--check'].includes(mode)) throw new Error('Usage: node scripts/build-action-site-browser-receipts.mjs --write|--check');
assert.equal(manifest.sites.length, 10);
const dispatchRows = fs.readFileSync(path.join(root, 'docs/action-pilots/dispatch-receipts.jsonl'), 'utf8')
  .trim().split('\n').map(line => JSON.parse(line));
assert.equal(dispatchRows.length, 10);
const receipts = [];
for (const [index, site] of manifest.sites.entries()) {
  const before = state(site, 'before');
  const after = state(site, 'after');
  assert.equal(withoutDuplicate(before.dom), after.dom, 'browser DOM changed beyond the duplicate');
  assert.equal(withoutDuplicate(before.source.toString('utf8')), after.source.toString('utf8'), 'source changed beyond the duplicate');
  assert.equal(before.record.contact_outer_html, after.record.contact_outer_html, 'contact path changed');
  assert.equal(before.record.title, after.record.title);
  const dispatch = dispatchRows[index];
  assert.equal(dispatch.pilot_id, site.id);
  const { receipt_sha256, ...dispatchBody } = dispatch;
  assert.equal(receipt_sha256, hash(dispatchBody));
  assert.equal(dispatch.source_before_commit, beforeCommit);
  assert.equal(dispatch.before_source_sha256, sha(before.source));
  assert.equal(dispatch.after_source_sha256, sha(after.source));
  assert.equal(dispatch.proposal.arguments.before_html_sha256, sha(before.source));
  assert.equal(dispatch.proposal.arguments.after_html_sha256, sha(after.source));
  assert.equal(dispatch.proposal.arguments.labels_sha256, hash(dispatch.declared_labels));
  assert.equal(dispatch.proposal.arguments.render_policy_sha256, hash(dispatch.render_policy));
  assert.equal(dispatch.plan.proposal_sha256, hash(dispatch.proposal));
  assert.equal(dispatch.dispatch_receipt.proposal_sha256, dispatch.plan.proposal_sha256);
  assert.equal(dispatch.dispatch_receipt.execution_status, 'dispatched');
  assert.equal(dispatch.callback_count, 1);
  assert.equal(dispatch.render_policy.decision, 'SUPPRESS');
  const body = { protocol: 'aml-controlled-site-browser-receipt/1', pilot_id: site.id,
    source_before_commit: beforeCommit, source_after_commit: afterCommit,
    declared_labels: dispatch.declared_labels, render_policy: dispatch.render_policy,
    host_policy: dispatch.host_policy, proposal: dispatch.proposal,
    plan: dispatch.plan, dispatch_receipt: dispatch.dispatch_receipt,
    dispatch_receipt_sha256: receipt_sha256, callback_count: dispatch.callback_count,
    before: { ...before.record, state_sha256: hash(before.record) },
    after: { ...after.record, state_sha256: hash(after.record) },
    claim_boundary: 'Ten observed paired pages on one project-controlled site. Screenshots and DOM snapshots are browser observations; declared labels and policy are project-authored.' };
  receipts.push({ ...body, receipt_sha256: hash(body) });
}
const file = path.join(evidenceDir, 'browser-receipts.jsonl');
const bytes = receipts.map(r => JSON.stringify(r)).join('\n') + '\n';
if (mode === '--write') fs.writeFileSync(file, bytes);
else assert.equal(fs.readFileSync(file, 'utf8'), bytes, 'paired browser receipts changed');
console.log(JSON.stringify({ pilots: receipts.length, before_screenshots: receipts.length,
  after_screenshots: receipts.length, before_dom: receipts.length, after_dom: receipts.length,
  contact_paths_preserved: receipts.length, first_receipt_sha256: receipts[0].receipt_sha256,
  receipts_file_sha256: sha(bytes) }));
