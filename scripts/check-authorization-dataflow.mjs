#!/usr/bin/env node
// Directive 010 data-flow check: runs the committed CodeQL queries in
// tooling/codeql/{javascript,python,go} against
//   --fixtures (default): the seeded bypass corpus in
//     tooling/codeql/authz-bypass-fixtures.json, one database per fixture,
//     and fails unless every bypass is flagged and no control is; or
//   --repo: this repository's own source, printing every alert.
// Needs the CodeQL CLI (CODEQL_CLI or `codeql` on PATH); without it the
// check fails closed (exit 2) instead of passing. No network is used: query
// dependencies resolve from the CLI distribution.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const QUERIES = {
  javascript: 'tooling/codeql/javascript/VerificationWithoutAuthorization.ql',
  python: 'tooling/codeql/python/VerificationWithoutAuthorization.ql',
  go: 'tooling/codeql/go/VerificationWithoutAuthorization.ql'
};

export function codeqlCli() {
  const candidates = [process.env.CODEQL_CLI, 'codeql'].filter(Boolean);
  for (const c of candidates) {
    const r = spawnSync(c, ['version', '--format=terse'], { encoding: 'utf8' });
    if (r.status === 0) return c;
  }
  return null;
}

function run(cli, args, cwd = root) {
  const r = spawnSync(cli, args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`codeql ${args.slice(0, 2).join(' ')} failed (${r.status}): ${(r.stderr || '').slice(-2000)}`);
  return r.stdout;
}

export function analyze(cli, language, sourceRoot, work) {
  const db = path.join(work, `db-${language}`);
  const create = ['database', 'create', db, `--language=${language}`, `--source-root=${sourceRoot}`, '--overwrite', '-q'];
  if (language === 'go') create.push('--build-mode=autobuild'); else create.push('--build-mode=none');
  run(cli, create);
  const bqrs = path.join(work, `${language}.bqrs`);
  run(cli, ['query', 'run', path.join(root, QUERIES[language]), '-d', db, '-o', bqrs, '-q']);
  const csv = run(cli, ['bqrs', 'decode', '--format=json', '--entities=url,string', bqrs]);
  const tuples = JSON.parse(csv)['#select']?.tuples ?? [];
  return tuples.map(t => ({ sink: t[0]?.label, message: t[1], source: t[2]?.label,
    file: t[0]?.url?.uri ? path.relative(sourceRoot, fileURLToPath(t[0].url.uri)) : null,
    line: t[0]?.url?.startLine ?? null }));
}

export function checkFixtures(cli, { only = null } = {}) {
  const corpus = JSON.parse(fs.readFileSync(path.join(root, 'tooling/codeql/authz-bypass-fixtures.json'), 'utf8'));
  const results = [];
  for (const [name, fx] of Object.entries(corpus.fixtures)) {
    if (only && !only.includes(name)) continue;
    const work = fs.mkdtempSync(path.join(os.tmpdir(), `aml-authz-df-${name}-`));
    try {
      const src = path.join(work, 'src');
      for (const [rel, text] of Object.entries(fx.files)) {
        fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
        fs.writeFileSync(path.join(src, rel), text);
      }
      const alerts = analyze(cli, fx.language, src, work);
      const flagged = alerts.length > 0;
      results.push({ fixture: name, language: fx.language, category: fx.category, expect_flagged: fx.expect_flagged,
        flagged, ok: flagged === fx.expect_flagged, alerts });
    } catch (error) {
      results.push({ fixture: name, language: fx.language, category: fx.category, expect_flagged: fx.expect_flagged,
        flagged: null, ok: false, error: String(error.message || error) });
    } finally {
      fs.rmSync(work, { recursive: true, force: true });
    }
  }
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cli = codeqlCli();
  if (!cli) {
    console.error('CodeQL CLI not found (set CODEQL_CLI). The data-flow check fails closed.');
    process.exit(2);
  }
  if (process.argv.includes('--repo')) {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-authz-df-repo-'));
    const out = {};
    try {
      for (const language of ['javascript', 'python', 'go']) {
        const src = language === 'go' ? path.join(root, 'independent/go') : root;
        out[language] = analyze(cli, language, src, work);
      }
    } finally { fs.rmSync(work, { recursive: true, force: true }); }
    console.log(JSON.stringify(out, null, 2));
  } else {
    const results = checkFixtures(cli);
    const failed = results.filter(r => !r.ok);
    console.log(JSON.stringify({ total: results.length, failed: failed.length, results }, null, 2));
    process.exitCode = failed.length ? 1 : 0;
  }
}
