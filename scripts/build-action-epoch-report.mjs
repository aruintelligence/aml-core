#!/usr/bin/env node
// Project-authored in-memory comparison of policy ABA with and without a
// host-owned monotonically increasing epoch. No external provider is called.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';
import { createEmailAdapter, createHttpAdapter, createDatabaseAdapter, createUiAdapter,
  mailResource, httpResource, databaseResource, uiResource } from '../pilots/action-boundary/receipt-adapters.mjs';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hash = value => sha(canonicalJSONStringify(value));
const secret = Buffer.from('public deterministic epoch fixture key, never use in production');
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
  const proposal = { protocol: 'aml-proposed-action/1', tool: fixture.tool,
    effect: fixture.effect, resource: fixture.resource(fixture.args),
    purpose: `Policy epoch fixture for ${fixture.id}`, arguments: fixture.args };
  const policy = { protocol: 'aml-action-policy/1', rules: [
    { tool: fixture.tool, effect: fixture.effect, resource: proposal.resource, requires_approval: true }] };
  const revokedPolicy = { protocol: 'aml-action-policy/1', rules: [] };
  const approve = async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 });

  let beforeCalls = 0;
  let beforePolicy = policy;
  const before = fixture.create({ ...fixture.host(() => { beforeCalls++; return { accepted: true }; }),
    policy: () => beforePolicy, authorize: approve, secret,
    nonce: () => `${fixture.id}-without-epoch` });
  const beforeReceipt = await before.issue(proposal);
  beforePolicy = revokedPolicy;
  beforePolicy = policy; // no adapter call sees the intervening policy
  const beforeOutcome = await before.dispatch(beforeReceipt, proposal);
  assert.equal(beforeOutcome.status, 'DISPATCHED');
  assert.equal(beforeCalls, 1);

  let attackCalls = 0;
  let attackPolicy = policy;
  let attackEpoch = 1;
  const guarded = fixture.create({ ...fixture.host(() => { attackCalls++; return { accepted: true }; }),
    policy: () => attackPolicy, policyEpoch: () => attackEpoch, authorize: approve, secret,
    nonce: () => `${fixture.id}-epoch-bound` });
  const guardedReceipt = await guarded.issue(proposal);
  assert.equal(guardedReceipt.policy_epoch, 1);
  attackPolicy = revokedPolicy;
  attackEpoch = 2;
  attackPolicy = policy;
  attackEpoch = 3;
  const attackOutcome = await guarded.dispatch(guardedReceipt, proposal);
  const attackReplay = await guarded.dispatch(guardedReceipt, proposal);
  assert.equal(attackOutcome.reason, 'policy_epoch_changed');
  assert.equal(attackReplay.reason, 'receipt_reused_or_unknown');
  assert.equal(attackCalls, 0);

  let approvalCalls = 0;
  let approvalPolicy = policy;
  let approvalEpoch = 1;
  const crossing = fixture.create({ ...fixture.host(() => { approvalCalls++; return { accepted: true }; }),
    policy: () => approvalPolicy, policyEpoch: () => approvalEpoch, secret,
    authorize: async ({ proposal_sha256 }) => {
      approvalPolicy = revokedPolicy;
      approvalEpoch = 2;
      approvalPolicy = policy;
      approvalEpoch = 3;
      return { approved: true, proposal_sha256 };
    }, nonce: () => `${fixture.id}-approval-aba` });
  const crossingReceipt = await crossing.issue(proposal);
  const crossingOutcome = await crossing.dispatch(crossingReceipt, proposal);
  assert.equal(crossingReceipt.decision, 'SUPPRESS');
  assert.equal(crossingReceipt.reason, 'policy_epoch_changed');
  assert.equal(crossingOutcome.reason, 'receipt_suppressed');
  assert.equal(approvalCalls, 0);

  let controlCalls = 0;
  const control = fixture.create({ ...fixture.host(() => { controlCalls++; return { accepted: true }; }),
    policy: () => policy, policyEpoch: () => 9, authorize: approve, secret,
    nonce: () => `${fixture.id}-unchanged-control` });
  const controlReceipt = await control.issue(proposal);
  const controlOutcome = await control.dispatch(controlReceipt, proposal);
  assert.equal(controlOutcome.status, 'DISPATCHED');
  assert.equal(controlCalls, 1);

  const body = { protocol: 'aml-receipt-policy-epoch-evidence/1', adapter: fixture.id,
    proposal, original_policy: policy, intervening_policy: revokedPolicy,
    without_epoch: { authorization_receipt: beforeReceipt, outcome: beforeOutcome,
      callback_count: beforeCalls },
    with_epoch: { authorization_receipt: guardedReceipt, outcome: attackOutcome,
      replay: attackReplay, callback_count: attackCalls },
    change_during_approval: { authorization_receipt: crossingReceipt,
      outcome: crossingOutcome, callback_count: approvalCalls },
    unchanged_epoch_control: { authorization_receipt: controlReceipt,
      outcome: controlOutcome, callback_count: controlCalls },
    claim_boundary: 'Project-authored local callbacks and public fixture key; the host epoch is simulated, not a durable provider.' };
  rows.push({ ...body, receipt_sha256: hash(body) });
}
const report = { protocol: 'aml-receipt-policy-epoch-report/1', adapters: rows,
  totals: { adapter_count: rows.length, comparison_callbacks: rows.length,
    epoch_bound_attack_callbacks: 0, approval_crossing_callbacks: 0,
    unchanged_control_callbacks: rows.length },
  claim_boundary: 'An unobserved policy A→B→A is detected only if the host supplies a reliable monotonic epoch. No external effects or independent validation.' };
const bytes = JSON.stringify(report, null, 2) + '\n';
const file = new URL('../docs/action-receipt-policy-epoch-report.json', import.meta.url);
const mode = process.argv[2];
if (mode === '--write') fs.writeFileSync(file, bytes);
else if (mode === '--check') assert.equal(fs.readFileSync(file, 'utf8'), bytes);
else throw Error('Usage: node scripts/build-action-epoch-report.mjs --write|--check');
console.log(JSON.stringify({ adapters: rows.length, comparison_callbacks: rows.length,
  epoch_bound_attack_callbacks: 0, approval_crossing_callbacks: 0,
  unchanged_control_callbacks: rows.length, report_sha256: sha(bytes) }));
