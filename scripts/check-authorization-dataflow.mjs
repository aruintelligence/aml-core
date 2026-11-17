#!/usr/bin/env node
// Directive 010 data-flow check: runs the committed CodeQL queries in
// tooling/codeql/{javascript,python,go} against
//   --fixtures (default): the seeded bypass corpus in
//     tooling/codeql/authz-bypass-fixtures.json, one database per fixture,
//     and fails unless every bypass is flagged and no control is; or
//   --repo: this repository's own source, printing every alert; or
//   --repo-gate <review.json>: the same scan, failing on any alert that is
//     not in the reviewed-alert inventory and on any inventory entry that no
//     longer matches an alert (stale). This is a ratchet, not a suppression:
//     every alert is still produced and printed, nothing is excluded from
//     the queries or the output, and source suppression comments are refused.
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

export function scanRepository(cli) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-authz-df-repo-'));
  const out = {};
  try {
    for (const language of ['javascript', 'python', 'go']) {
      const src = language === 'go' ? path.join(root, 'independent/go') : root;
      out[language] = analyze(cli, language, src, work).map(alert => {
        const file = language === 'go' && alert.file ? `independent/go/${alert.file}` : alert.file;
        let code = null;
        try { code = fs.readFileSync(path.join(root, file), 'utf8').split(/\r?\n/)[alert.line - 1].trim(); } catch {}
        return { ...alert, file, code };
      });
    }
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
  return out;
}

export const REVIEW_CLASSES = Object.freeze(['diagnostic-non-authorizing', 'self-check-script',
  'precondition-deny-guard', 'non-authorization-report']);

/** CodeQL/LGTM source suppression comments anywhere in tracked source are refused. */
export function sourceSuppressions(dir = root) {
  const found = [];
  const skip = new Set(['.git', 'node_modules']);
  const walk = d => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      if (skip.has(entry.name)) continue;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(?:[cm]?js|py|go|ts|mts)$/.test(entry.name)) {
        const text = fs.readFileSync(full, 'utf8');
        text.split(/\r?\n/).forEach((line, index) => {
          if (/(?:\/\/|#)\s*(?:codeql|lgtm)\[/i.test(line)) found.push(`${path.relative(dir, full)}:${index + 1}`);
        });
      }
    }
  };
  walk(dir);
  return found;
}

export function gateRepository(alerts, review, suppressions = []) {
  const failures = suppressions.map(s => `source suppression comment refused: ${s}`);
  if (review?.schema !== 'aml-authz-dataflow-review/1' || !Array.isArray(review.entries)) {
    return { failures: [...failures, 'review inventory schema invalid'], matched: 0, total: 0 };
  }
  const key = (language, file, code) => `${language}|${file}|${code}`;
  const reviewed = new Map();
  for (const e of review.entries) {
    if (!REVIEW_CLASSES.includes(e.class) || typeof e.why !== 'string' || e.why.length < 20) {
      failures.push(`review entry without a valid class and reason: ${e.file} ${e.code}`);
    }
    reviewed.set(key(e.language, e.file, e.code), { ...e, seen: 0 });
  }
  let total = 0; let matched = 0;
  for (const [language, list] of Object.entries(alerts)) {
    for (const a of list) {
      total += 1;
      const entry = reviewed.get(key(language, a.file, a.code));
      if (entry) { entry.seen += 1; matched += 1; }
      else failures.push(`unreviewed alert: ${language} ${a.file}:${a.line} ${a.code} -- ${a.message}`);
    }
  }
  for (const e of reviewed.values()) {
    if (e.seen === 0) failures.push(`stale review entry (no alert): ${e.language} ${e.file} ${e.code}`);
  }
  return { failures, matched, total };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cli = codeqlCli();
  if (!cli) {
    console.error('CodeQL CLI not found (set CODEQL_CLI). The data-flow check fails closed.');
    process.exit(2);
  }
  if (process.argv.includes('--repo') || process.argv.includes('--repo-gate')) {
    const out = scanRepository(cli);
    if (process.argv.includes('--repo-gate')) {
      const reviewFile = process.argv[process.argv.indexOf('--repo-gate') + 1];
      if (!reviewFile) { console.error('usage: --repo-gate <review.json>'); process.exit(2); }
      const review = JSON.parse(fs.readFileSync(path.resolve(reviewFile), 'utf8'));
      const gate = gateRepository(out, review, sourceSuppressions());
      console.log(JSON.stringify({ ...gate, alerts: out }, null, 2));
      process.exitCode = gate.failures.length ? 1 : 0;
    } else {
      console.log(JSON.stringify(out, null, 2));
    }
  } else {
    const results = checkFixtures(cli);
    const failed = results.filter(r => !r.ok);
    console.log(JSON.stringify({ total: results.length, failed: failed.length, results }, null, 2));
    process.exitCode = failed.length ? 1 : 0;
  }
}
