#!/usr/bin/env node
// New cohort; the original adapter report remains byte-for-byte unchanged in
// the append-only registry. All callbacks here are in-memory fakes.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';
import { createEmailAdapter, createHttpAdapter, createDatabaseAdapter, createUiAdapter,
  mailResource, httpResource, databaseResource, uiResource } from '../pilots/action-boundary/receipt-adapters.mjs';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hash = value => sha(canonicalJSONStringify(value));
const secret = Buffer.from('public deterministic revocation key, never use in production');
const fixtures = [
  { id: 'email', create: createEmailAdapter, tool: 'send_email', effect: 'send',
    resource: mailResource, args: { to: 'team@example.test', cc: [], bcc: [], subject: 'Update', body: 'Ready' },
    host: callback => ({ provider: { send: callback } }) },
  { id: 'http', create: createHttpAdapter, tool: 'http_request', effect: 'write',
    resource: httpResource, args: { url: 'https://api.example.test/v1/status', method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: '{"ready":true}' },
    host: callback => ({ fetchImpl: callback }) },
  { id: 'database', create: createDatabaseAdapter, tool: 'database_write', effect: 'write',
    resource: databaseResource, args: { table: 'records', key: 'r42', value: { status: 'ready' } },
    host: callback => ({ database: { put: callback } }) },
  { id: 'ui', create: createUiAdapter, tool: 'render_ui', effect: 'write',
    resource: uiResource, args: { root: '#status', text: 'Ready' },
    host: callback => ({ renderer: { setText: callback } }) }
];

const rows = [];
for (const fixture of fixtures) {
  let callbackCount = 0;
  const callback = () => { callbackCount++; return { accepted: true }; };
  const proposal = { protocol: 'aml-proposed-action/1', tool: fixture.tool,
    effect: fixture.effect, resource: fixture.resource(fixture.args),
    purpose: `Revocation fixture for ${fixture.id}`, arguments: fixture.args };
  const policy = { protocol: 'aml-action-policy/1', rules: [
    { tool: fixture.tool, effect: fixture.effect, resource: proposal.resource, requires_approval: true }] };
  const revokedPolicy = { protocol: 'aml-action-policy/1', rules: [] };
  const host = fixture.host(callback);
  let currentPolicy = policy;
  const adapter = fixture.create({ ...host, secret, policy: () => currentPolicy,
    authorize: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
    nonce: () => `${fixture.id}-observed-revocation` });
  const issued = await adapter.issue(proposal);
  assert.equal(issued.decision, 'ALLOW');
  currentPolicy = revokedPolicy;
  const revoked = await adapter.dispatch(issued, proposal);
  assert.equal(revoked.reason, 'policy_changed');
  currentPolicy = policy;
  const restored = await adapter.dispatch(issued, proposal);
  assert.equal(restored.reason, 'receipt_reused_or_unknown');

  let approvalPolicy = policy;
  const duringApproval = fixture.create({ ...host, secret, policy: () => approvalPolicy,
    authorize: async ({ proposal_sha256 }) => {
      approvalPolicy = revokedPolicy;
      return { approved: true, proposal_sha256 };
    }, nonce: () => `${fixture.id}-approval-revoked` });
  const suppressed = await duringApproval.issue(proposal);
  assert.equal(suppressed.decision, 'SUPPRESS');
  assert.equal(suppressed.reason, 'policy_changed');
  approvalPolicy = policy;
  const afterRestoration = await duringApproval.dispatch(suppressed, proposal);
  assert.equal(afterRestoration.reason, 'receipt_suppressed');
  assert.equal(callbackCount, 0);
  const body = { protocol: 'aml-receipt-revocation-evidence/1', adapter: fixture.id,
    proposal, original_policy: policy, revoked_policy: revokedPolicy,
    observed_revocation: { authorization_receipt: issued, revoked, after_restoration: restored },
    revocation_during_approval: { authorization_receipt: suppressed, after_restoration: afterRestoration },
    callback_count: callbackCount,
    claim_boundary: 'Project-authored in-memory provider callbacks and a public test key; no external effect or independent validation.' };
  rows.push({ ...body, receipt_sha256: hash(body) });
}
const report = { protocol: 'aml-receipt-revocation-report/1', adapters: rows,
  totals: { adapter_count: rows.length, blocked_paths: rows.length * 4, callback_count: 0 },
  claim_boundary: 'One observed policy change and one approval-time change per adapter, each followed by restoration. No claim about an unobserved policy ABA or external provider.' };
const bytes = JSON.stringify(report, null, 2) + '\n';
const file = new URL('../docs/action-receipt-revocation-report.json', import.meta.url);
const mode = process.argv[2];
if (mode === '--write') fs.writeFileSync(file, bytes);
else if (mode === '--check') assert.equal(fs.readFileSync(file, 'utf8'), bytes);
else throw Error('Usage: node scripts/build-action-revocation-report.mjs --write|--check');
console.log(JSON.stringify({ adapters: rows.length, blocked_paths: rows.length * 4,
  callback_count: 0, report_sha256: sha(bytes) }));
