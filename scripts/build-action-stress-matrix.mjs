#!/usr/bin/env node
// Five project-maintained bindings replay the full 375-case stress cohort.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runReferenceCase } from '../pilots/action-boundary/challenge-reference-adapter.mjs';
import { runWebCryptoCase } from '../docs/action-webcrypto-boundary.js';
import { checkObserved, sha256Canonical } from './verify-action-boundary-expanded.mjs';

const root = new URL('../', import.meta.url);
const casesBytes = fs.readFileSync(new URL('conformance/action-stress-375-cases.json', root));
const receiptBytes = fs.readFileSync(new URL('conformance/action-stress-375-receipts.jsonl', root));
const corpus = JSON.parse(casesBytes);
const receipts = receiptBytes.toString('utf8').trimEnd().split('\n').map(JSON.parse);
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const sourceHash = file => sha(fs.readFileSync(new URL(file, root)));
assert.equal(corpus.protocol, 'aml-action-stress-challenge/1');
assert.equal(corpus.cases.length, receipts.length);
assert.equal(corpus.cases.length, 375);
const runtimes = [
  ['javascript_node', null],
  ['python_hashlib', ['python3', 'pilots/action-boundary/challenge-python-adapter.py']],
  ['perl_digest_sha', ['perl', 'pilots/action-boundary/perl_boundary.pl']],
  ['python_openssl', ['python3', 'pilots/action-boundary/openssl_python_boundary.py']],
  ['webcrypto_node_host', null]
];
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-action-stress-'));
const rows = [];
let callbacks = 0, blocked = 0;
try {
  for (const [index, row] of corpus.cases.entries()) {
    const receipt = receipts[index];
    const { receipt_sha256, ...body } = receipt;
    assert.equal(receipt_sha256, sha256Canonical(body), row.id);
    assert.equal(receipt.case_id, row.id);
    assert.deepEqual(receipt.proposal, row.proposal);
    assert.deepEqual(receipt.host_policy, row.policy);
    assert.deepEqual(receipt.host_fixture, row.host);
    assert.equal(receipt.proposal_input_sha256, sha256Canonical(row.proposal));
    assert.equal(receipt.initial_policy_sha256, sha256Canonical(row.policy));
    assert.deepEqual(receipt.expected_plan, row.expected.plan);
    assert.deepEqual(receipt.expected_dispatch_receipt, row.expected.receipt);
    assert.equal(receipt.expected_tool_calls, row.expected.tool_calls);
    assert.deepEqual(receipt.expected_executed_proposal, row.expected.executed_proposal);
    const input = { protocol: 'aml-action-challenge-case/1', case_id: row.id,
      proposal: row.proposal, policy: row.policy, host: row.host };
    const caseFile = path.join(temp, `${row.id}.json`);
    fs.writeFileSync(caseFile, JSON.stringify(input));
    const matches = {};
    for (const [name, command] of runtimes) {
      let result;
      if (name === 'javascript_node') result = await runReferenceCase(input);
      else if (name === 'webcrypto_node_host') result = await runWebCryptoCase(input);
      else {
        const execution = spawnSync(command[0], [command[1], caseFile],
          { cwd: root.pathname, encoding: 'utf8', timeout: 5000, maxBuffer: 256 * 1024 });
        assert.equal(execution.status, 0, `${row.id} ${name}: ${execution.stderr || execution.error}`);
        result = JSON.parse(execution.stdout.trim());
      }
      checkObserved(row, result);
      matches[name] = true;
    }
    callbacks += row.expected.tool_calls;
    blocked += row.expected.receipt.execution_status === 'blocked';
    rows.push({ case_id: row.id, proposal_sha256: row.expected.plan.proposal_sha256,
      initial_policy_sha256: receipt.initial_policy_sha256,
      decision: row.expected.plan.decision, gate_outcome: row.expected.tool_calls ? 'ALLOW' : 'SUPPRESS',
      execution_status: row.expected.receipt.execution_status,
      callback_count: row.expected.tool_calls, receipt_sha256, matches });
  }
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
const py = spawnSync('python3', ['scripts/verify-action-stress-375.py'],
  { cwd: root.pathname, encoding: 'utf8', timeout: 30000 });
assert.equal(py.status, 0, py.stderr || py.error);
const pyResult = JSON.parse(py.stdout.trim());
assert.deepEqual(pyResult, { cases: 375, receipts: 375, blocked, callbacks });
const report = { protocol: 'aml-action-stress-five-runtime-matrix/1',
  scope: '375 project-maintained simulated host cases; WebCrypto module executed under Node, not a claim of browser observation',
  cases_sha256: sha(casesBytes), receipts_sha256: sha(receiptBytes),
  source_sha256: {
    javascript_node: sourceHash('pilots/action-boundary/boundary.mjs'),
    python_hashlib: sourceHash('pilots/action-boundary/python_boundary.py'),
    perl_digest_sha: sourceHash('pilots/action-boundary/perl_boundary.pl'),
    python_openssl: sourceHash('pilots/action-boundary/openssl_python_boundary.py'),
    webcrypto_node_host: sourceHash('docs/action-webcrypto-boundary.js')
  },
  cases: rows.length, matches_by_runtime: Object.fromEntries(runtimes.map(([name]) => [name, rows.length])),
  callbacks, blocked, rows };
const bytes = JSON.stringify(report, null, 2) + '\n';
const file = new URL('../docs/action-stress-five-runtime-report.json', import.meta.url);
const mode = process.argv[2];
if (mode === '--write') fs.writeFileSync(file, bytes);
else if (mode === '--check') assert.equal(fs.readFileSync(file, 'utf8'), bytes);
else throw Error('Usage: node scripts/build-action-stress-matrix.mjs --write|--check');
console.log(JSON.stringify({ cases: rows.length, matches: report.matches_by_runtime, callbacks, blocked,
  report_sha256: sha(bytes), first_receipt_sha256: rows[0].receipt_sha256 }));
