#!/usr/bin/env node
// Deterministic project-authored integration fixtures. No external provider is called.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';
import { createEmailAdapter, createHttpAdapter, createDatabaseAdapter, createUiAdapter,
  mailResource, httpResource, databaseResource, uiResource } from '../pilots/action-boundary/receipt-adapters.mjs';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hash = value => sha(canonicalJSONStringify(value));
const copy = value => structuredClone(value);
const fixtures = [
  { id: 'email', tool: 'send_email', effect: 'send', create: createEmailAdapter, resource: mailResource,
    args: { to: 'team@example.test', cc: ['review@example.test'], bcc: [], subject: 'Report', body: 'Build passed.' },
    change: args => { args.bcc.push('outside@example.test'); },
    host: callback => ({ provider: { send: callback } }), requires_approval: true },
  { id: 'http', tool: 'http_request', effect: 'write', create: createHttpAdapter, resource: httpResource,
    args: { url: 'https://api.example.test/v1/status', method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"ready":true}' },
    change: args => { args.url = 'https://other.example.test/v1/status'; },
    host: callback => ({ fetchImpl: callback }), requires_approval: false },
  { id: 'database', tool: 'database_write', effect: 'write', create: createDatabaseAdapter, resource: databaseResource,
    args: { table: 'records', key: 'r42', value: { status: 'ready' } },
    change: args => { args.key = 'other'; },
    host: callback => ({ database: { put: callback } }), requires_approval: false },
  { id: 'ui', tool: 'render_ui', effect: 'write', create: createUiAdapter, resource: uiResource,
    args: { root: '#status', text: 'Ready' },
    change: args => { args.root = '#other'; },
    host: callback => ({ renderer: { setText: callback } }), requires_approval: false }
];

const rows = [];
for (const fixture of fixtures) {
  let callbackCount = 0;
  const callback = async (...args) => { callbackCount++; return { accepted: true, args }; };
  const proposal = { protocol: 'aml-proposed-action/1', tool: fixture.tool, effect: fixture.effect,
    resource: fixture.resource(fixture.args), purpose: `Controlled ${fixture.id} adapter`, arguments: copy(fixture.args) };
  const policy = { protocol: 'aml-action-policy/1', rules: [
    { tool: fixture.tool, effect: fixture.effect, resource: proposal.resource,
      requires_approval: fixture.requires_approval }] };
  let sequence = 0;
  const adapter = fixture.create({ ...fixture.host(callback), policy: () => policy,
    secret: Buffer.from('public deterministic fixture key, never use in production'),
    authorize: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
    nonce: () => `${fixture.id}-${++sequence}` });
  const before = callbackCount;
  const noReceipt = await adapter.dispatch(null, proposal);
  const receipt = await adapter.issue(proposal);
  assert.equal(receipt.decision, 'ALLOW');
  assert.equal(receipt.proposal_sha256, hash(proposal));
  const changed = copy(proposal);
  fixture.change(changed.arguments);
  const changedTarget = await adapter.dispatch(receipt, changed);
  const changedPayload = copy(proposal);
  changedPayload.arguments.fixture_note = 'injected';
  const tamperedPayload = await adapter.dispatch(receipt, changedPayload);
  const changedReceipt = await adapter.dispatch({ ...receipt, resolved_target: 'forged' }, proposal);
  const suppressed = await adapter.issue({ ...copy(proposal), resource: 'wrong:resource' });
  const deniedReceipt = await adapter.dispatch(suppressed, { ...copy(proposal), resource: 'wrong:resource' });
  assert.equal(callbackCount, 0, 'unreceipted or changed input invoked callback');
  const authorized = await adapter.dispatch(receipt, proposal);
  assert.equal(authorized.status, 'DISPATCHED');
  assert.equal(callbackCount, 1);
  const replay = await adapter.dispatch(receipt, proposal);
  const secondReceipt = await adapter.issue(proposal);
  policy.rules.length = 0;
  const revoked = await adapter.dispatch(secondReceipt, proposal);
  assert.equal(callbackCount, 1);
  const observations = { no_receipt: noReceipt, changed_target: changedTarget,
    changed_payload: tamperedPayload, changed_receipt: changedReceipt,
    declared_target_mismatch: deniedReceipt, valid: authorized, replay, policy_revoked: revoked };
  for (const [id, outcome] of Object.entries(observations)) {
    assert.equal(outcome.callback_count, id === 'valid' ? 1 : 0, `${fixture.id}/${id}`);
  }
  const rowBody = { protocol: 'aml-receipt-adapter-evidence/1', adapter: fixture.id,
    proposal, host_policy: receipt.host_policy, authorization_receipt: receipt,
    observations, callback_count_before: before, callback_count_after: callbackCount,
    claim_boundary: 'Project-maintained local callbacks and a public test signing key. No email, HTTP request, database, or browser UI side effect was sent to an external service.' };
  rows.push({ ...rowBody, receipt_sha256: hash(rowBody) });
}
const report = { protocol: 'aml-receipt-adapter-report/1', adapters: rows,
  totals: { adapter_count: rows.length, callbacks_before: 0, callbacks_after: rows.length,
    blocked_variants: rows.length * 7, dispatched: rows.length },
  claim_boundary: 'These are deterministic local adapter fixtures, not independent field validation.' };
const bytes = JSON.stringify(report, null, 2) + '\n';
const file = new URL('../docs/action-receipt-adapters-report.json', import.meta.url);
const mode = process.argv[2];
if (mode === '--write') fs.writeFileSync(file, bytes);
else if (mode === '--check') assert.equal(fs.readFileSync(file, 'utf8'), bytes);
else throw Error('Usage: node scripts/build-action-receipt-adapters-report.mjs --write|--check');
console.log(JSON.stringify({ adapters: rows.length, callbacks_before: 0, callbacks_after: rows.length,
  blocked_variants: rows.length * 7, report_sha256: sha(bytes), first_receipt_sha256: rows[0].receipt_sha256 }));
