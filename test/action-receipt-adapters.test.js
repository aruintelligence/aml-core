import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';
import { createReceiptBoundAdapter, createUiAdapter, uiResource } from '../pilots/action-boundary/receipt-adapters.mjs';

const sha = value => crypto.createHash('sha256').update(canonicalJSONStringify(value)).digest('hex');
const args = { root: '#status', text: 'Ready' };
const proposal = { protocol: 'aml-proposed-action/1', tool: 'render_ui', effect: 'write',
  resource: uiResource(args), purpose: 'Fixture', arguments: args };
const policy = { protocol: 'aml-action-policy/1', rules: [
  { tool: 'render_ui', effect: 'write', resource: proposal.resource, requires_approval: false }] };

test('a recomputed hash cannot forge a host MAC or invoke the callback', async () => {
  let calls = 0;
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => policy, secret: Buffer.alloc(32, 7) });
  const receipt = await adapter.issue(proposal);
  const { host_mac_sha256: oldMac, receipt_sha256: oldHash, ...body } = receipt;
  const forgedBody = { ...body, proposal: { ...body.proposal, arguments: { root: '#other', text: 'Ready' } } };
  const forged = { ...forgedBody, receipt_sha256: sha(forgedBody), host_mac_sha256: oldMac };
  assert.notEqual(oldHash, forged.receipt_sha256);
  assert.equal((await adapter.dispatch(forged, forgedBody.proposal)).callback_count, 0);
  assert.equal(calls, 0);
  assert.equal((await adapter.dispatch(receipt, proposal)).callback_count, 1);
  assert.equal((await adapter.dispatch(receipt, proposal)).callback_count, 0);
  assert.equal(calls, 1);
});

test('a throwing provider yields UNKNOWN and consumes the one-use receipt', async () => {
  let calls = 0;
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; throw Error('partial effect possible'); } },
    policy: () => policy, secret: Buffer.alloc(32, 8) });
  const receipt = await adapter.issue(proposal);
  assert.equal((await adapter.dispatch(receipt, proposal)).status, 'UNKNOWN');
  assert.equal((await adapter.dispatch(receipt, proposal)).callback_count, 0);
  assert.equal(calls, 1);
});

test('a grant observed under revoked policy cannot resurrect when that policy is restored', async () => {
  let calls = 0;
  let currentPolicy = policy;
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => currentPolicy, secret: Buffer.alloc(32, 9) });
  const receipt = await adapter.issue(proposal);
  currentPolicy = { protocol: 'aml-action-policy/1', rules: [] };
  const revoked = await adapter.dispatch(receipt, proposal);
  assert.equal(revoked.reason, 'policy_changed');
  assert.equal(revoked.callback_count, 0);
  currentPolicy = policy;
  const restored = await adapter.dispatch(receipt, proposal);
  assert.equal(restored.reason, 'receipt_reused_or_unknown');
  assert.equal(restored.callback_count, 0);
  assert.equal(calls, 0);
});

test('an approval spanning policy revocation cannot mint a live receipt', async () => {
  let calls = 0;
  let currentPolicy = { protocol: 'aml-action-policy/1', rules: [
    { tool: 'render_ui', effect: 'write', resource: proposal.resource, requires_approval: true }] };
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => currentPolicy, secret: Buffer.alloc(32, 10),
    authorize: async ({ proposal_sha256 }) => {
      currentPolicy = { protocol: 'aml-action-policy/1', rules: [] };
      return { approved: true, proposal_sha256 };
    } });
  const receipt = await adapter.issue(proposal);
  assert.equal(receipt.decision, 'SUPPRESS');
  assert.equal(receipt.reason, 'policy_changed');
  currentPolicy = { protocol: 'aml-action-policy/1', rules: [
    { tool: 'render_ui', effect: 'write', resource: proposal.resource, requires_approval: true }] };
  const outcome = await adapter.dispatch(receipt, proposal);
  assert.equal(outcome.callback_count, 0);
  assert.equal(calls, 0);
});

test('an approval spanning a target mapping change cannot mint a live receipt', async () => {
  let calls = 0;
  let target = proposal.resource;
  const approvalPolicy = { protocol: 'aml-action-policy/1', rules: [
    { tool: 'render_ui', effect: 'write', resource: proposal.resource, requires_approval: true }] };
  const adapter = createReceiptBoundAdapter({ tool: 'render_ui', effect: 'write',
    policy: () => approvalPolicy, secret: Buffer.alloc(32, 11),
    resolveTarget: () => target, execute: () => { calls++; },
    authorize: async ({ proposal_sha256 }) => {
      target = 'ui:#other';
      return { approved: true, proposal_sha256 };
    } });
  const receipt = await adapter.issue(proposal);
  assert.equal(receipt.decision, 'SUPPRESS');
  assert.equal(receipt.reason, 'target_changed');
  target = proposal.resource;
  assert.equal((await adapter.dispatch(receipt, proposal)).callback_count, 0);
  assert.equal(calls, 0);
});

test('a grant observed under changed target mapping is spent before restoration', async () => {
  let calls = 0;
  let target = proposal.resource;
  const adapter = createReceiptBoundAdapter({ tool: 'render_ui', effect: 'write',
    policy: () => policy, secret: Buffer.alloc(32, 12),
    resolveTarget: () => target, execute: () => { calls++; } });
  const receipt = await adapter.issue(proposal);
  target = 'ui:#other';
  const changed = await adapter.dispatch(receipt, proposal);
  assert.equal(changed.reason, 'target_mismatch');
  target = proposal.resource;
  const restored = await adapter.dispatch(receipt, proposal);
  assert.equal(restored.reason, 'receipt_reused_or_unknown');
  assert.equal(restored.callback_count, 0);
  assert.equal(calls, 0);
});

test('a host policy epoch detects an unobserved revoke and restore', async () => {
  let calls = 0;
  let currentPolicy = policy;
  let epoch = 1;
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => currentPolicy, policyEpoch: () => epoch, secret: Buffer.alloc(32, 13) });
  const receipt = await adapter.issue(proposal);
  currentPolicy = { protocol: 'aml-action-policy/1', rules: [] };
  epoch = 2;
  currentPolicy = policy;
  epoch = 3;
  const outcome = await adapter.dispatch(receipt, proposal);
  assert.equal(outcome.reason, 'policy_epoch_changed');
  assert.equal(outcome.callback_count, 0);
  assert.equal((await adapter.dispatch(receipt, proposal)).reason, 'receipt_reused_or_unknown');
  assert.equal(calls, 0);
});

test('a host epoch changed away and back during approval suppresses issuance', async () => {
  let calls = 0;
  let epoch = 1;
  let currentPolicy = { protocol: 'aml-action-policy/1', rules: [
    { tool: 'render_ui', effect: 'write', resource: proposal.resource, requires_approval: true }] };
  const originalPolicy = currentPolicy;
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => currentPolicy, policyEpoch: () => epoch, secret: Buffer.alloc(32, 14),
    authorize: async ({ proposal_sha256 }) => {
      currentPolicy = { protocol: 'aml-action-policy/1', rules: [] };
      epoch = 2;
      currentPolicy = originalPolicy;
      epoch = 3;
      return { approved: true, proposal_sha256 };
    } });
  const receipt = await adapter.issue(proposal);
  assert.equal(receipt.decision, 'SUPPRESS');
  assert.equal(receipt.reason, 'policy_epoch_changed');
  assert.equal((await adapter.dispatch(receipt, proposal)).callback_count, 0);
  assert.equal(calls, 0);
});

test('the policy epoch is signed and an unchanged epoch can dispatch', async () => {
  let calls = 0;
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => policy, policyEpoch: () => 7, secret: Buffer.alloc(32, 15) });
  const receipt = await adapter.issue(proposal);
  assert.equal(receipt.policy_epoch, 7);
  const forged = { ...receipt, policy_epoch: 8 };
  assert.equal((await adapter.dispatch(forged, proposal)).reason, 'invalid_receipt');
  assert.equal((await adapter.dispatch(receipt, proposal)).status, 'DISPATCHED');
  assert.equal(calls, 1);
});

test('an unavailable epoch spends the grant and a malformed initial epoch fails closed', async () => {
  let calls = 0;
  let unavailable = false;
  const adapter = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => policy, policyEpoch: () => {
      if (unavailable) throw Error('epoch store unavailable');
      return 4;
    }, secret: Buffer.alloc(32, 16) });
  const receipt = await adapter.issue(proposal);
  unavailable = true;
  assert.equal((await adapter.dispatch(receipt, proposal)).reason, 'policy_epoch_unavailable');
  unavailable = false;
  assert.equal((await adapter.dispatch(receipt, proposal)).reason, 'receipt_reused_or_unknown');
  assert.equal(calls, 0);
  const bad = createUiAdapter({ renderer: { setText: () => { calls++; } },
    policy: () => policy, policyEpoch: () => Number.NaN, secret: Buffer.alloc(32, 17) });
  await assert.rejects(bad.issue(proposal), /invalid_policy_epoch/);
  assert.equal(calls, 0);
});
