// Static policy: no execution or acceptance path may treat `valid` alone as
// permission. scripts/check-valid-field-decisions.mjs enumerates every read of
// a `valid` field and every success-status decision sink; each must be
// classified in audit/AML_VALID_FIELD_DECISION_INVENTORY.json. These tests run
// the check on the repository and prove that it rejects seeded violations.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanRepository, scanSource, scanDecisionSinks, checkInventory, checkDecisionSinks,
  REQUIRED_DECISION_SINKS, INVENTORY_PATH } from '../scripts/check-valid-field-decisions.mjs';

const inventory = JSON.parse(fs.readFileSync(INVENTORY_PATH, 'utf8'));

test('every valid read and decision sink in the repository is classified and none is valid-only', () => {
  const { findings, sinks } = scanRepository();
  assert.ok(findings.length > 100, 'scan found the known reads');
  assert.deepEqual(checkInventory(findings, inventory), []);
  assert.deepEqual(checkDecisionSinks(sinks, inventory), []);
  const run = spawnSync(process.execPath, ['scripts/check-valid-field-decisions.mjs'], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  for (const sink of REQUIRED_DECISION_SINKS) {
    assert.ok(fs.readFileSync(sink.file, 'utf8').includes(sink.pattern), sink.effect);
  }
});

const classify = (findings, category, extra = {}) => ({ ...inventory,
  entries: findings.map(f => ({ file: f.file, line: f.line, code: f.code, category, effect: 'seeded fixture', ...extra })) });

test('seeded valid-only positive sinks are rejected whatever category they claim', () => {
  const seeded = {
    'runtime/seeded-exit.js': 'process.exit(result.valid ? 0 : 1);',
    'server/seeded-http.js': 'return send(res, verification?.valid ? 200 : 422, verification, headers);',
    'pilots/seeded-if.mjs': 'if (check.valid) { executeTool(call); }',
    'docs/seeded-assign.js': 'const authorized = check.valid;',
    'docs/seeded-assign2.js': 'return { allowed: report.valid === true };',
    'pilots/seeded-py.py': 'accepted = result["valid"]\nif result["valid"]:\n    run()'
  };
  for (const [file, source] of Object.entries(seeded)) {
    const findings = scanSource(file, source).map(f => ({ ...f, scope: 'shipped' }));
    assert.ok(findings.length > 0, `${file} read found`);
    for (const category of ['deny-guard', 'conjunct', 'signed-verdict-count', 'schema-check', 'validator-exit', 'assertion']) {
      const failures = checkInventory(findings, classify(findings, category, { conjunct_with: 'claimed' }));
      assert.ok(failures.length > 0, `${file} accepted as ${category}`);
    }
  }
  const sinks = scanDecisionSinks('runtime/seeded.js', 'process.exitCode = r.valid ? 0 : 2;\nsend(res, r.valid === true ? 200 : 403);');
  assert.equal(sinks.length, 2);
  for (const category of ['explicit-decision', 'conjunct', 'validator-exit']) {
    const failures = checkDecisionSinks(sinks, { ...inventory, decision_sinks: sinks.map(s => ({ ...s, category, effect: 'seeded fixture' })) });
    const flagged = new Set(failures.map(f => f.split(':')[1]));
    assert.deepEqual([...flagged].sort(), ['1', '2'], `${category}: ${failures}`);
  }
  const alias = scanDecisionSinks('independent/seeded.py', 'return 0 if accepted else 1');
  const aliasFailures = checkDecisionSinks(alias, { ...inventory, decision_sinks: alias.map(s =>
    ({ ...s, category: 'explicit-decision', effect: 'seeded fixture', alias_of_valid: true })) });
  assert.ok(aliasFailures.length >= 1 && aliasFailures.every(f => f.startsWith('independent/seeded.py:1:')),
    'a reviewed alias of valid cannot pass as an explicit decision');
});

test('unclassified, stale and comment/string-only reads are handled exactly', () => {
  const findings = scanSource('runtime/new.js', [
    '// if (x.valid) { run(); }',
    "const text = 'process.exit(r.valid ? 0 : 1)';",
    'const t = `${r.valid ? "a" : "b"}`;',
    'if (!r.valid) throw new Error("x");'
  ].join('\n'));
  assert.deepEqual(findings.map(f => f.line), [3, 4], 'comments and plain strings are ignored; template expressions are not');
  const unclassified = checkInventory(findings, { ...inventory, entries: [] });
  assert.equal(unclassified.filter(f => f.includes('unclassified')).length, 2);
  const stale = checkInventory([], classify(findings, 'deny-guard'));
  assert.equal(stale.filter(f => f.includes('stale')).length, 2);
  const notNegated = checkInventory([findings[0]], classify([findings[0]], 'deny-guard'));
  assert.ok(notNegated.some(f => f.includes('not negated')));
});

test('removing an explicit decision from a required sink fails the check', t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-valid-sinks-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  for (const sink of REQUIRED_DECISION_SINKS) {
    fs.mkdirSync(path.join(base, path.dirname(sink.file)), { recursive: true });
    fs.copyFileSync(sink.file, path.join(base, sink.file));
  }
  assert.deepEqual(checkInventory([], { ...inventory, entries: [] }, base), []);
  const http = path.join(base, 'server/httpServer.js');
  fs.writeFileSync(http, fs.readFileSync(http, 'utf8').replace('result.authorized === true ? 200', 'result.valid ? 200'));
  const failures = checkInventory([], { ...inventory, entries: [] }, base);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /server\/httpServer\.js: required explicit decision sink missing/);
});

test('HTML pages cannot hide a valid read behind tag spelling, inline handlers, or a missing end tag', () => {
  const pages = {
    'docs/seeded-end-tag-space.html': '<script>let a = 1;</script >\n<p>x</p>\n<script>if (r.valid) go();</script>',
    'docs/seeded-upper.html': '<SCRIPT type="module">\nif (r.valid) go();\n</SCRIPT>',
    'docs/seeded-handler.html': '<button onclick="if (r.valid) go()">run</button>',
    'docs/seeded-unterminated.html': '<p>x</p>\n<script>\nif (r.valid) go();\n'
  };
  for (const [file, source] of Object.entries(pages)) {
    const lines = scanSource(file, source).map(f => f.line);
    const expected = source.split('\n').findIndex(l => l.includes('r.valid')) + 1;
    assert.deepEqual(lines, [expected], file);
  }
  assert.deepEqual(scanSource('docs/seeded-comment.html', '<!-- if (r.valid) go(); -->\n<p>.valid</p>').map(f => f.line), [2],
    'HTML comments are blanked; other markup stays visible (fail-safe over-reporting)');
});
