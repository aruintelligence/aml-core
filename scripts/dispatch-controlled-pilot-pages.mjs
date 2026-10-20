#!/usr/bin/env node
// Host-owned file render dispatch. The frozen, approved callback writes after pages.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';
import { planAction, dispatchAction } from '../pilots/action-boundary/boundary.mjs';
import { html } from './build-controlled-pilot-pages.mjs';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'pilots/action-boundary/controlled-sites.json')));
const sha = value => crypto.createHash('sha256').update(value, 'utf8').digest('hex');
const hash = value => sha(canonicalJSONStringify(value));
const escape = s => String(s).replaceAll('&', '&amp;').replaceAll('"', '&quot;');
const targetRegex = /\n    <aside id="redundant-contact"[\s\S]*?<\/aside>/g;

export function validateSingleRemoval(before, after, site, contactHref) {
  const targets = [...before.matchAll(targetRegex)];
  assert.equal(targets.length, 1, 'exactly one declared duplicate target required');
  assert.equal((after.match(targetRegex) || []).length, 0, 'duplicate remains in after state');
  assert.equal(before.replace(targetRegex, ''), after, 'after state changed more than the duplicate element');
  const link = `<a href="${escape(contactHref)}">${escape(site.action)}</a>`;
  assert.ok(targets[0][0].includes(link), 'duplicate action does not match declared contact path');
  const intentional = `<a id="contact-action" href="${escape(contactHref)}">${escape(site.action)}</a>`;
  assert.ok(before.includes(intentional) && after.includes(intentional), 'intentional contact path is missing');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  if (!['--write', '--check'].includes(mode)) throw new Error('Usage: node scripts/dispatch-controlled-pilot-pages.mjs --write|--check');
  assert.equal(manifest.sites.length, 10);
  const receipts = [];
  for (const site of manifest.sites) {
    const name = `${site.id}-${site.slug}.html`;
    const beforeFile = path.join(root, 'docs/action-pilots/before', name);
    const afterFile = path.join(root, 'docs/action-pilots/after', name);
    const before = fs.readFileSync(beforeFile, 'utf8');
    const after = html(site, 'after');
    assert.equal(before, html(site, 'before'), 'before source checkpoint changed');
    validateSingleRemoval(before, after, site, manifest.contact_href);
    const declaredLabels = { target: 'redundant_duplicate', target_selector: '#redundant-contact',
      contact_selector: '#contact-action', duplicated_action: site.action, duplicated_href: manifest.contact_href,
      provenance: 'project-authored controlled-site fixture' };
    const renderPolicy = { protocol: 'aml-controlled-render-policy/1', decision: 'SUPPRESS',
      rule: 'remove exactly one declared duplicate with identical action text and href; preserve intentional contact link' };
    const proposal = { protocol: 'aml-proposed-action/1', tool: 'render_ui', effect: 'write',
      resource: `page:${site.id}`, purpose: 'Suppress exactly one redundant contact element',
      arguments: { site_id: site.id, target_selector: '#redundant-contact', operation: 'remove_exact_element',
        before_html_sha256: sha(before), after_html_sha256: sha(after),
        labels_sha256: hash(declaredLabels), render_policy_sha256: hash(renderPolicy) } };
    const hostPolicy = { protocol: 'aml-action-policy/1', rules: [
      { tool: 'render_ui', effect: 'write', resource: `page:${site.id}`, requires_approval: true }] };
    const plan = planAction(proposal, hostPolicy);
    assert.equal(plan.decision, 'requires_approval');
    let callbackCount = 0;
    const outcome = await dispatchAction(proposal, { policy: hostPolicy,
      requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
      executeTool: async frozen => {
        assert.deepEqual(frozen, proposal, 'frozen payload changed');
        assert.equal(fs.readFileSync(beforeFile, 'utf8'), before, 'before state changed at dispatch');
        validateSingleRemoval(before, after, site, manifest.contact_href);
        if (mode === '--write') {
          fs.mkdirSync(path.dirname(afterFile), { recursive: true });
          fs.writeFileSync(afterFile, after);
        } else assert.equal(fs.readFileSync(afterFile, 'utf8'), after, 'after source changed');
        callbackCount++;
        return sha(after);
      } });
    assert.equal(outcome.receipt.execution_status, 'dispatched');
    assert.equal(outcome.result, sha(after));
    assert.equal(callbackCount, 1);
    const body = { protocol: 'aml-controlled-site-dispatch-receipt/1', pilot_id: site.id,
      source_before_commit: '877a8f8d64adf2d44c27dda73f1efe9f88d60418',
      declared_labels: declaredLabels, render_policy: renderPolicy, host_policy: hostPolicy,
      proposal, plan, dispatch_receipt: outcome.receipt, callback_count: callbackCount,
      before_source_sha256: sha(before), after_source_sha256: sha(after),
      claim_boundary: 'Project-controlled generated page and host callback, not independent live-site validation.' };
    receipts.push({ ...body, receipt_sha256: hash(body) });
  }
  const reportFile = path.join(root, 'docs/action-pilots/dispatch-receipts.jsonl');
  const bytes = receipts.map(r => JSON.stringify(r)).join('\n') + '\n';
  if (mode === '--write') fs.writeFileSync(reportFile, bytes);
  else assert.equal(fs.readFileSync(reportFile, 'utf8'), bytes, 'dispatch receipts changed');
  console.log(JSON.stringify({ mode, pilots: receipts.length, callback_count: receipts.reduce((n, r) => n + r.callback_count, 0),
    first_receipt_sha256: receipts[0].receipt_sha256, report_sha256: sha(bytes) }));
}
