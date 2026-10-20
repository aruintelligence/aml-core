#!/usr/bin/env node
// Independent expected-result construction for 25 profiles × 15 mutations.
// Never copy expected outcomes from a runtime under test.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';

const copy = value => structuredClone(value);
const hash = value => crypto.createHash('sha256').update(canonicalJSONStringify(value)).digest('hex');
const hex = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const families = ['mail', 'http', 'database', 'ui', 'payment'];
const bodies = ['café', 'Σ review', '例: plan', '🚀 test', 'line one\nline two'];
const scenarios = [
  ['baseline', 'Exact host rule and frozen payload.'],
  ['reorder-top', 'Object key order cannot alter the proposal digest.'],
  ['reorder-nested', 'Nested key order cannot alter the proposal digest.'],
  ['payload-stale', 'Stale grant blocks an approval-required changed payload; an unreviewed rule exposes the counterexample.'],
  ['resource-changed', 'Changed declared resource has no exact host rule.'],
  ['argument-target-changed', 'Counterexample: generic rule cannot resolve the destination inside arbitrary tool arguments.'],
  ['policy-target-changed', 'Rule for a different resource denies.'],
  ['duplicate-rule', 'Ambiguous policy denies with a null plan digest.'],
  ['invalid-policy', 'Malformed host policy denies with a null plan digest.'],
  ['extra-field', 'Extra proposal field denies with a null plan digest.'],
  ['approval-missing', 'Missing approval hook blocks when approval is required.'],
  ['approval-throws', 'Throwing approval hook blocks when approval is required.'],
  ['policy-revoked', 'Policy removed while awaiting approval blocks before callback.'],
  ['callback-throws', 'A throwing callback has UNKNOWN external outcome and no automatic retry.'],
  ['caller-mutates', 'Caller mutation after digest never reaches the frozen callback.']
];
const profiles = [];
for (const family of families) for (let n = 1; n <= 5; n++) {
  const suffix = `${family}-${n}`;
  const body = `${bodies[n - 1]} / ${suffix}`;
  const metadata = { '10': 'ten', '2': 'two', '01': 'zero-one', locale: bodies[n - 1], nested: { z: n, a: [true, null, body] } };
  let tool, effect, resource, args, targetField, changedTarget;
  if (family === 'mail') {
    tool = 'send_message'; effect = 'send'; resource = `recipient${n}@example.test`;
    args = { to: resource, cc: [], bcc: [], subject: `Update ${n}`, body, metadata };
    targetField = 'to'; changedTarget = `outside${n}@example.test`;
  } else if (family === 'http') {
    tool = 'http_request'; effect = 'write'; resource = `https://api.example.test/v2/items/${n}`;
    args = { url: resource, method: 'POST', headers: { Accept: 'application/json' }, body, metadata };
    targetField = 'url'; changedTarget = `https://other.example.test/v2/items/${n}`;
  } else if (family === 'database') {
    tool = 'write_record'; effect = 'write'; resource = `record:${n}`;
    args = { path: resource, value: { status: 'draft', index: n }, body, metadata };
    targetField = 'path'; changedTarget = `record:other-${n}`;
  } else if (family === 'ui') {
    tool = 'render_ui'; effect = 'write'; resource = `screen:${n}`;
    args = { root: `#screen-${n}`, text: body, functionCallId: `render-${n}`, body, metadata };
    targetField = 'root'; changedTarget = `#other-${n}`;
  } else {
    tool = 'request_payment'; effect = 'pay'; resource = `invoice:${n}`;
    args = { account: resource, amount_cents: n * 100001, currency: 'USD', body, metadata };
    targetField = 'account'; changedTarget = `invoice:other-${n}`;
  }
  profiles.push({ family, n, tool, effect, resource, args, targetField, changedTarget,
    requiresApproval: n % 2 === 1 });
}

const rows = [];
for (const profile of profiles) for (const [scenario, intent] of scenarios) {
  const proposal = { protocol: 'aml-proposed-action/1', tool: profile.tool,
    effect: profile.effect, resource: profile.resource,
    purpose: `Stress profile ${profile.family} ${profile.n}`, arguments: copy(profile.args) };
  const original = copy(proposal);
  const policy = { protocol: 'aml-action-policy/1', rules: [
    { tool: profile.tool, effect: profile.effect, resource: profile.resource,
      requires_approval: profile.requiresApproval }] };
  const host = { approval: profile.requiresApproval ? 'matching' : 'missing', tool: 'return' };
  const expected = { decision: profile.requiresApproval ? 'requires_approval' : 'allow',
    reason: 'exact_rule', status: 'dispatched', receiptReason: 'host_dispatch_returned', calls: 1 };
  switch (scenario) {
    case 'reorder-top': {
      const reordered = Object.fromEntries(Object.entries(proposal).reverse());
      for (const key of Object.keys(proposal)) delete proposal[key];
      Object.assign(proposal, reordered);
      break;
    }
    case 'reorder-nested':
      proposal.arguments.metadata = Object.fromEntries(Object.entries(proposal.arguments.metadata).reverse());
      break;
    case 'payload-stale':
      proposal.arguments.body += ' / changed after original grant';
      if (profile.requiresApproval) {
        Object.assign(host, { approval: 'fixed', approval_digest_sha256: hash(original) });
        Object.assign(expected, { status: 'blocked', receiptReason: 'approval_missing_or_mismatched', calls: 0 });
      }
      break;
    case 'resource-changed':
      proposal.resource = `other:${profile.family}:${profile.n}`;
      Object.assign(expected, { decision: 'deny', reason: 'no_exact_rule', status: 'blocked', receiptReason: 'no_exact_rule', calls: 0 });
      break;
    case 'argument-target-changed':
      proposal.arguments[profile.targetField] = profile.changedTarget;
      break;
    case 'policy-target-changed':
      policy.rules[0].resource = `wrong:${profile.family}:${profile.n}`;
      Object.assign(expected, { decision: 'deny', reason: 'no_exact_rule', status: 'blocked', receiptReason: 'no_exact_rule', calls: 0 });
      break;
    case 'duplicate-rule':
      policy.rules.push(copy(policy.rules[0]));
      Object.assign(expected, { decision: 'deny', reason: 'ambiguous_policy', status: 'blocked', receiptReason: 'ambiguous_policy', calls: 0 });
      break;
    case 'invalid-policy':
      policy.protocol = 'other-policy/1';
      Object.assign(expected, { decision: 'deny', reason: 'invalid_policy', status: 'blocked', receiptReason: 'invalid_policy', calls: 0 });
      break;
    case 'extra-field':
      proposal.undeclared = true;
      Object.assign(expected, { decision: 'deny', reason: 'invalid_proposal', status: 'blocked', receiptReason: 'invalid_proposal', calls: 0 });
      break;
    case 'approval-missing':
      host.approval = 'missing';
      if (profile.requiresApproval) Object.assign(expected, { status: 'blocked', receiptReason: 'approval_unavailable', calls: 0 });
      break;
    case 'approval-throws':
      host.approval = 'throw';
      if (profile.requiresApproval) Object.assign(expected, { status: 'blocked', receiptReason: 'approval_error', calls: 0 });
      break;
    case 'policy-revoked':
      host.remove_policy_rule = true;
      if (profile.requiresApproval) Object.assign(expected, { status: 'blocked', receiptReason: 'policy_changed', calls: 0 });
      break;
    case 'callback-throws':
      host.tool = 'throw';
      Object.assign(expected, { status: 'unknown', receiptReason: 'host_dispatch_error' });
      break;
    case 'caller-mutates':
      host.mutate_proposal_body = 'MUTATED AFTER DIGEST';
      break;
  }
  const nullDigest = ['invalid_proposal', 'invalid_policy', 'ambiguous_policy'].includes(expected.reason);
  const proposalDigest = nullDigest ? null : hash(proposal);
  const plan = { protocol: 'aml-action-plan/1', proposal_sha256: proposalDigest,
    decision: expected.decision, reason: expected.reason };
  const dispatchReceipt = { protocol: 'aml-action-dispatch/1', proposal_sha256: proposalDigest,
    policy_decision: expected.decision, execution_status: expected.status, reason: expected.receiptReason };
  const id = `stress-${profile.family}-${profile.n}-${scenario}`;
  rows.push({ protocol: 'aml-action-expanded-case/1', id, intent, proposal, policy, host,
    expected: { plan, receipt: dispatchReceipt, tool_calls: expected.calls,
      executed_proposal: expected.calls ? copy(proposal) : null },
    receipt_schema: 'protocol/action-boundary-evidence-receipt.schema.json' });
}
assert.equal(rows.length, 375);
assert.equal(new Set(rows.map(r => r.id)).size, 375);
const corpus = { protocol: 'aml-action-stress-challenge/1', project_authored: true,
  profile_count: profiles.length, mutation_count: scenarios.length,
  cases: rows, claim_boundary: '375 deterministic simulated-host fixtures across 25 profiles and 15 mutation classes; no external tool effects or independent validators.' };
const receipts = rows.map(row => {
  const body = { protocol: 'aml-action-boundary-evidence-receipt/1', case_id: row.id,
    provenance: 'project-authored stress fixture with simulated host callback',
    proposal: row.proposal, host_policy: row.policy, host_fixture: row.host,
    expected_plan: row.expected.plan, expected_dispatch_receipt: row.expected.receipt,
    expected_tool_calls: row.expected.tool_calls, expected_executed_proposal: row.expected.executed_proposal,
    proposal_input_sha256: hash(row.proposal), initial_policy_sha256: hash(row.policy) };
  return { ...body, receipt_sha256: hash(body) };
});
const caseFile = new URL('../conformance/action-stress-375-cases.json', import.meta.url);
const receiptFile = new URL('../conformance/action-stress-375-receipts.jsonl', import.meta.url);
const caseBytes = JSON.stringify(corpus, null, 2) + '\n';
const receiptBytes = receipts.map(r => JSON.stringify(r)).join('\n') + '\n';
const mode = process.argv[2];
if (mode === '--write') { fs.writeFileSync(caseFile, caseBytes); fs.writeFileSync(receiptFile, receiptBytes); }
else if (mode === '--check') {
  assert.equal(fs.readFileSync(caseFile, 'utf8'), caseBytes);
  assert.equal(fs.readFileSync(receiptFile, 'utf8'), receiptBytes);
} else throw Error('Usage: node scripts/build-action-stress-375.mjs --write|--check');
console.log(JSON.stringify({ profiles: profiles.length, mutations: scenarios.length, cases: rows.length,
  receipts: receipts.length, case_file_sha256: hex(caseBytes), receipt_file_sha256: hex(receiptBytes),
  first_receipt_sha256: receipts[0].receipt_sha256 }));
