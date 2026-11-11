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
  REQUIRED_DECISION_SINKS, INVENTORY_PATH, REVIEWED_DIAGNOSTIC_EXITS } from '../scripts/check-valid-field-decisions.mjs';

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
    for (const category of ['deny-guard', 'conjunct', 'signed-verdict-count', 'schema-check', 'consistency-status', 'diagnostic-exit', 'report-only', 'assertion']) {
      const failures = checkInventory(findings, classify(findings, category, { conjunct_with: 'claimed' }));
      assert.ok(failures.length > 0, `${file} accepted as ${category}`);
    }
  }
  const sinks = scanDecisionSinks('runtime/seeded.js', 'process.exitCode = r.valid ? 0 : 2;\nsend(res, r.valid === true ? 200 : 403);');
  assert.deepEqual([...new Set(sinks.map(s => s.line))], [1, 2]);
  for (const category of ['explicit-decision', 'conjunct', 'diagnostic-exit', 'non-decision']) {
    const failures = checkDecisionSinks(sinks, { ...inventory, decision_sinks: sinks.map(s => ({ ...s, category, effect: 'seeded fixture' })) });
    const flagged = new Set(failures.map(f => f.split(':')[1]));
    assert.deepEqual([...flagged].sort(), ['1', '2'], `${category}: ${failures}`);
  }
  // A validator command no longer has a valid-only exit category.
  const legacy = scanDecisionSinks('bin/seeded-validator.js', 'process.exit(result.valid ? 0 : 1);');
  assert.ok(checkDecisionSinks(legacy, { ...inventory, decision_sinks: legacy.map(s =>
    ({ ...s, category: 'validator-exit', effect: 'seeded fixture' })) }).some(f => /unknown sink category|valid alone/.test(f)));
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

// Adversarial alias (data-flow) cases: each hides a valid-only success
// behind a variable, destructuring, helper, property, subscript, inversion
// or implicit success. Every one must surface as a valid-only sink.
const jsBypasses = {
  'subscript': "if (r['valid']) execute();",
  'variable': 'const ok = r.valid;\nif (ok) execute();',
  'transitive': 'const a = r.valid;\nconst b = a && true;\nprocess.exitCode = b ? 0 : 2;',
  'destructure': 'const { valid } = r;\nif (valid) execute();',
  'destructure-rename': 'const { valid: fine } = r;\nprocess.exit(fine ? 0 : 1);',
  'helper': 'function isOk(r) { return r.valid; }\nif (isOk(x)) execute();',
  'arrow-helper': 'const isOk = r => r?.valid === true;\nsend(res, isOk(x) ? 200 : 403);',
  'property': 'const out = { go: r.valid };\nif (out.go) execute();',
  'object-assign': 'Object.assign(state, { go: r.valid });\nif (state.go) execute();',
  'boolean-wrap': 'const ok = Boolean(r.valid);\nprocess.exit(ok ? 0 : 1);',
  'inverted-exit': 'process.exit(!r.valid ? 1 : 0);',
  'implicit-success': 'if (!r.valid) process.exitCode = 2;',
  'implicit-success-block': 'if (!r.valid) {\n  process.exitCode = 2;\n}',
  'computed-code': 'const code = r.valid ? 0 : 1;\nprocess.exit(code);',
  'status-code': 'res.statusCode = r.valid ? 200 : 403;'
};

function validOnlyFailures(rel, source) {
  const findings = scanSource(rel, source).map(f => ({ ...f, scope: 'shipped' }));
  const sinks = scanDecisionSinks(rel, source);
  const readFailures = checkInventory(findings, classify(findings, 'conjunct', { conjunct_with: 'claimed' }))
    .filter(f => /controls a positive/.test(f));
  const sinkFailures = checkDecisionSinks(sinks, { ...inventory, decision_sinks: sinks.map(s =>
    ({ ...s, category: 'explicit-decision', effect: 'seeded fixture' })) }).filter(f => /reads valid|valid alone/.test(f));
  return [...readFailures, ...sinkFailures];
}

test('JavaScript aliases of valid cannot hide a valid-only success', () => {
  for (const [name, source] of Object.entries(jsBypasses)) {
    assert.ok(validOnlyFailures(`pilots/seeded-${name}.js`, source).length > 0, `${name} bypass not caught`);
  }
  // Controls: an explicit decision in the same expression is not valid-only.
  for (const source of ['const ok = r.valid && r.authorized === true;\nif (ok) execute();',
    'process.exit(r.authorized === true ? 0 : 3);', 'if (!r.valid) throw new Error("x");']) {
    assert.deepEqual(validOnlyFailures('pilots/seeded-control.js', source), [], source);
  }
});

test('Python aliases of valid are found by the AST data-flow pass', () => {
  const pyBypasses = {
    'subscript-alias': 'ok = result["valid"]\nreturn 0 if ok else 1',
    'get-alias': 'ok = result.get("valid") is True\nif ok:\n    run()',
    'helper': 'def fine(r):\n    return r["valid"]\nsys.exit(0 if fine(x) else 1)',
    'dict-property': 'out = {"go": result["valid"]}\nif out["go"]:\n    run()',
    'implicit-success': 'if not result["valid"]:\n    return 1\nreturn 0',
    'inverted': 'return 1 if not result["valid"] else 0'
  };
  for (const [name, source] of Object.entries(pyBypasses)) {
    assert.ok(validOnlyFailures(`independent/seeded_${name.replace(/-/g, '_')}.py`, source).length > 0, `${name} bypass not caught`);
  }
});

test('an imported valid-derived helper is tracked across modules', t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-valid-alias-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  fs.mkdirSync(path.join(base, 'pilots'), { recursive: true });
  fs.writeFileSync(path.join(base, 'pilots/helper.mjs'), 'export function accepted(r) { return r.valid === true; }\n');
  fs.writeFileSync(path.join(base, 'pilots/caller.mjs'),
    "import { accepted as fine } from './helper.mjs';\nif (fine(result)) execute();\nprocess.exit(fine(result) ? 0 : 1);\n");
  const { findings, sinks } = scanRepository(base);
  const caller = findings.filter(f => f.file === 'pilots/caller.mjs');
  assert.deepEqual(caller.map(f => f.line), [2, 3]);
  assert.ok(caller.every(f => f.kind === 'alias'));
  const failures = checkDecisionSinks(sinks.filter(s => s.file === 'pilots/caller.mjs'), { ...inventory,
    decision_sinks: sinks.filter(s => s.file === 'pilots/caller.mjs').map(s => ({ ...s, category: 'explicit-decision', effect: 'seeded fixture' })) }, base);
  assert.ok(failures.some(f => /pilots\/caller\.mjs:3: explicit-decision gate reads valid/.test(f)), failures.join('\n'));
});

test('a diagnostic exit must be reviewed and stay under its diagnostic guard', t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-valid-diag-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  for (const entry of REVIEWED_DIAGNOSTIC_EXITS) {
    fs.mkdirSync(path.join(base, path.dirname(entry.file)), { recursive: true });
    fs.copyFileSync(entry.file, path.join(base, entry.file));
  }
  const diag = inventory.decision_sinks.filter(e => e.category === 'diagnostic-exit');
  assert.deepEqual([...new Set(diag.map(e => `${e.file}:${e.code}`))].sort(),
    REVIEWED_DIAGNOSTIC_EXITS.map(e => `${e.file}:${e.code}`).sort());
  const sinksOf = b => REVIEWED_DIAGNOSTIC_EXITS.flatMap(e => scanDecisionSinks(e.file, fs.readFileSync(path.join(b, e.file), 'utf8')))
    .filter(s => diag.some(d => d.file === s.file && d.code === s.code));
  const inv = sinks => ({ ...inventory, decision_sinks: sinks.map(s => ({ ...s, category: 'diagnostic-exit', effect: 'reviewed' })) });
  assert.deepEqual(checkDecisionSinks(sinksOf(base), inv(sinksOf(base)), base), []);
  // Removing the guard (exit 0 for any consistent result) must fail.
  const shared = path.join(base, 'runtime/commandAuthorization.js');
  fs.writeFileSync(shared, fs.readFileSync(shared, 'utf8').replace('  if (diagnosticOnly) {', '  if (true) {'));
  assert.ok(checkDecisionSinks(sinksOf(base), inv(sinksOf(base)), base).some(f => /without its guard/.test(f)));
  // An unreviewed valid-only exit cannot claim the diagnostic category.
  const seeded = scanDecisionSinks('bin/seeded.js', 'if (diagnosticOnly) {\n  process.exit(r.valid ? 0 : 1);\n}');
  assert.ok(checkDecisionSinks(seeded, inv(seeded), base).some(f => /not in REVIEWED_DIAGNOSTIC_EXITS/.test(f)));
});

test('the check fails closed when the Python data-flow pass cannot run', t => {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-valid-nopython-'));
  t.after(() => fs.rmSync(bin, { recursive: true, force: true }));
  fs.symlinkSync(process.execPath, path.join(bin, 'node'));
  const run = spawnSync(process.execPath, ['scripts/check-valid-field-decisions.mjs'],
    { encoding: 'utf8', env: { PATH: bin } });
  assert.notEqual(run.status, 0, run.stdout);
  assert.match(run.stderr + run.stdout, /python data-flow pass failed/);
});
