import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';
import { createUiAdapter, uiResource } from '../pilots/action-boundary/receipt-adapters.mjs';

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
