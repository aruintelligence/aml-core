#!/usr/bin/env node
// Policy check: a `valid` field is never, by itself, permission to execute.
//
// Many AML verifiers return `valid`, which means internal consistency or
// integrity of an artifact. It does not say that the relying party's own
// trust inputs (retained challenge, held policy, trusted clock, trust roots)
// were satisfied. This check enumerates every read of a `valid` field in
// shipped source (JavaScript, HTML module scripts, and Python) and requires
// each one to be classified in audit/AML_VALID_FIELD_DECISION_INVENTORY.json.
// Unclassified reads, stale inventory lines, and positive decision sinks
// (process exit 0, HTTP 2xx, `if (x.valid) {`, decision-named assignments)
// controlled by `valid` alone fail the check. Reads under test/ are scanned for
// those positive sinks as well. The check is lexical, not a proof of data
// flow; see the inventory `method` field for its limits.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const INVENTORY_PATH = 'audit/AML_VALID_FIELD_DECISION_INVENTORY.json';
const SKIP_DIRS = new Set(['.git', 'node_modules', '.codeql', 'coverage']);
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.html', '.py', '.go']);

export const CATEGORIES = Object.freeze({
  'deny-guard': 'valid=false denies (throw/return/exit non-zero/skip); a true value only lets later checks run.',
  'conjunct': 'valid is one conjunct of a decision that also requires an explicit decision field or trust input.',
  'signed-verdict-count': 'a signer verdict counted toward a quorum; permission additionally requires a relying-party-held policy.',
  'report-only': 'copied into an output, report, log or display; no action is gated on it.',
  'schema-check': 'type or shape check of a verdict field; malformed input is rejected.',
  'validator-exit': 'exit status of a validator command whose documented meaning is format/integrity validity only; it executes nothing.',
  'assertion': 'test or self-check assertion; not an execution path.'
});

// Fields that are explicit decisions or relying-party trust inputs.
const EXPLICIT = /\b(authorized|verified|requested_conditions_met|official|claim_verified|policy_met|threshold_met|witness_met|inputs_met|trusted|isTrusted|eligible|accepted|temporal_validation|trusted_distinct_signers|countMatches|signatureValid|signature_valid|replayValid|chain\.valid|errors\.length|semantic_proof_valid|registry_valid)\b/;

// Decision sinks whose meaning must not come from `valid` alone.
export const REQUIRED_DECISION_SINKS = Object.freeze([
  { file: 'server/httpServer.js', pattern: 'return send(res, result.authorized === true ? 200 : 422, {',
    effect: 'HTTP 200 for /v1/verify-witness-bundle' },
  { file: 'bin/aml.js', pattern: 'process.exit(result.authorized === true ? 0 : 2);',
    effect: 'exit 0 for aml verify-witness' },
  { file: 'docs/aml-signed-verification-quorum.js', pattern: 'witness.authorized === true',
    effect: 'witness_met inside the signed quorum' },
  { file: 'docs/detached-verifier.html', pattern: "check.authorized === true ? 'ok' : 'bad'",
    effect: 'detached verifier pass styling' },
  { file: 'docs/worker-verifier.html', pattern: "event.data?.authorized === true ? 'ok' : 'bad'",
    effect: 'worker verifier pass styling' }
]);

// Blank comments and string/template contents (keeping newlines and length)
// so that code reads are found and text inside strings is ignored.
export function maskJavaScript(source) {
  const out = source.split('');
  const blank = (from, to) => { for (let i = from; i < to; i += 1) if (out[i] !== '\n') out[i] = ' '; };
  let i = 0;
  const n = source.length;
  const templateDepth = [];
  let prevSignificant = '';
  while (i < n) {
    const c = source[i];
    const d = source[i + 1];
    if (c === '/' && d === '/') { const e = source.indexOf('\n', i); const end = e < 0 ? n : e; blank(i, end); i = end; continue; }
    if (c === '/' && d === '*') { const e = source.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; blank(i, end); i = end; continue; }
    if (c === '\'' || c === '"') {
      let j = i + 1;
      while (j < n && source[j] !== c && source[j] !== '\n') j += source[j] === '\\' ? 2 : 1;
      blank(i + 1, Math.min(j, n)); i = j + 1; prevSignificant = 'str'; continue;
    }
    if (c === '`' || (c === '}' && templateDepth.length && templateDepth[templateDepth.length - 1] === 0)) {
      if (c === '}') templateDepth.pop();
      let j = i + 1;
      while (j < n && source[j] !== '`' && !(source[j] === '$' && source[j + 1] === '{')) j += source[j] === '\\' ? 2 : 1;
      blank(i + 1, Math.min(j, n));
      if (source[j] === '$') { templateDepth.push(0); i = j + 2; } else { i = j + 1; }
      prevSignificant = 'str';
      continue;
    }
    if (c === '/' && /^(|[(,=:[!&|?{};+\-*%<>~^]|return|typeof|case|throw)$/.test(prevSignificant)) {
      // Regular expression literal.
      let j = i + 1; let cls = false;
      while (j < n && source[j] !== '\n') {
        if (source[j] === '\\') { j += 2; continue; }
        if (source[j] === '[') cls = true; else if (source[j] === ']') cls = false;
        else if (source[j] === '/' && !cls) break;
        j += 1;
      }
      blank(i + 1, Math.min(j, n)); i = j + 1; prevSignificant = 'str'; continue;
    }
    if (templateDepth.length) {
      if (c === '{') templateDepth[templateDepth.length - 1] += 1;
      else if (c === '}') templateDepth[templateDepth.length - 1] -= 1;
    }
    if (!/\s/.test(c)) {
      if (/[\w$]/.test(c)) {
        let j = i; while (j < n && /[\w$]/.test(source[j])) j += 1;
        prevSignificant = source.slice(i, j); i = j; continue;
      }
      prevSignificant = c;
    }
    i += 1;
  }
  return out.join('');
}

export function maskPython(source) {
  const out = source.split('');
  const blank = (from, to) => { for (let i = from; i < to; i += 1) if (out[i] !== '\n') out[i] = ' '; };
  let i = 0; const n = source.length;
  while (i < n) {
    const c = source[i];
    if (c === '#') { const e = source.indexOf('\n', i); const end = e < 0 ? n : e; blank(i, end); i = end; continue; }
    if (c === '\'' || c === '"') {
      const triple = source.slice(i, i + 3) === c.repeat(3);
      if (triple) { const e = source.indexOf(c.repeat(3), i + 3); const end = e < 0 ? n : e; blank(i + 3, end); i = end + 3; continue; }
      let j = i + 1;
      while (j < n && source[j] !== c && source[j] !== '\n') j += source[j] === '\\' ? 2 : 1;
      // Keep short key literals visible: they name fields read in subscripts.
      if (!/^[A-Za-z_]\w{0,63}$/.test(source.slice(i + 1, j))) blank(i + 1, Math.min(j, n));
      i = j + 1; continue;
    }
    i += 1;
  }
  return out.join('');
}

function htmlScripts(source) {
  // Scan the whole page, preserving offsets. Markup (inline handlers and
  // attribute values included) stays as written apart from blanked HTML
  // comments; only <script> bodies get JavaScript comment/string masking.
  // End tags of any case, with whitespace or junk before `>`, close a body;
  // an unterminated <script> runs to the end of the file (fail-safe: it is
  // still scanned).
  const blank = text => text.replace(/[^\n]/g, ' ');
  const markup = text => text.replace(/<!--[\s\S]*?(?:-->|$)/g, blank);
  const re = /(<script\b[^>]*>)([\s\S]*?)(<\/script\b[^>]*>|$)/gi;
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(source))) {
    out += markup(source.slice(last, m.index)) + m[1] + maskJavaScript(m[2]) + m[3];
    last = m.index + m[0].length;
    if (m[3] === '') break;
  }
  return out + markup(source.slice(last));
}

const JS_READ = /(?:\?\.|(?<![.\w$])\.|(?<=[\w$\])])\s*\.)valid(?![\w$])|\[\s*(['"])valid\1\s*\]/g;
const JS_DESTRUCTURE = /\{[^{}=]*\bvalid\b[^{}]*\}\s*=(?!=)/g;
const PY_READ = /\[\s*(['"])valid\1\s*\]|\.get\(\s*(['"])valid\2|(?<=[\w)\]])\.valid(?![\w])/g;

function walk(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, files);
    else if (entry.isFile() && CODE_EXT.has(path.extname(entry.name))) files.push(full);
  }
  return files;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

// Positive decision sinks controlled only by `valid` (lexical). The gate is
// the expression text that decides a success outcome.
export function validOnlyPositiveSinks(maskedLine) {
  // A non-negated `valid` read (JS member, Python subscript or .get), optionally
  // compared with `=== true` / `is True`.
  const v = String.raw`\(?\s*[\w$][\w$.?\[\]]*?(?:(?:\?\.|\.)valid\b|\[\s*['"]valid['"]\s*\]|\.get\(\s*['"]valid['"]\s*\))\s*\)?(?:\s*(?:===\s*true|is\s+True))?`;
  const patterns = {
    exit: new RegExp(String.raw`process\.exit(?:Code\s*=\s*|\s*\(\s*)${v}\s*\?\s*0\b`),
    http: new RegExp(String.raw`(?:send|status|writeHead)\s*\([^)]*?,?\s*${v}\s*\?\s*2\d\d\b`),
    if: new RegExp(String.raw`\b(?:if|elif|while)\s*\(?\s*(?!!|not\b)${v}\s*(?:\)\s*(?:\{|[\w$])|:)`),
    assign: new RegExp(String.raw`\b(?:authorized|allowed|permitted|execute|accepted|approve|approved|ok)\s*(?:[:=]|\bis\b)\s*(?!!|not\b)${v}\s*(?:[,;})]|$)`),
    'py-exit': /return\s+0\s+if\s+[\w$.]*(?:\[\s*['"]valid['"]\s*\]|\.valid)\s+else/
  };
  return Object.entries(patterns).filter(([, re]) => re.test(maskedLine)).map(([kind]) => kind);
}

// Positive `if (x.valid)` branches reviewed in code (not just in the
// inventory): each is a counted signed verdict or has its other conjunct on
// the immediately preceding guard. Adding one requires changing this check.
// Decision-named aliases of `valid` that feed only a validator exit status.
// They remain valid-only (reported as such) and are pinned here for review.
export const REVIEWED_VALIDATOR_ALIASES = Object.freeze([
  { file: 'independent/python/wire_runtime.py', code: 'accepted = result["valid"]',
    why: 'wire runtime verify CLI: exit status reports artifact integrity/structure only; executes nothing' }
]);

export const REVIEWED_POSITIVE_IF = Object.freeze([
  { file: 'docs/aml-signed-verification-quorum.js', code: 'if (envelope.report.valid) {',
    why: 'counts an authenticated positive report toward threshold_met; authorized requires a held policy' },
  { file: 'docs/aml-signed-verification-quorum.js', code: 'if (signature.valid) {',
    why: 'preceded by `envelope?.report?.valid !== true || !allowed.has(fingerprint)) continue`; feeds the held-policy trusted set' },
  { file: 'independent/python/verify_signed_quorum.py', code: 'elif envelope["report"]["valid"]:',
    why: 'Python mirror of the signed-verdict count' }
]);

function maskFor(rel, source) {
  const ext = path.extname(rel);
  return ext === '.py' ? maskPython(source) : ext === '.html' ? htmlScripts(source) : maskJavaScript(source);
}

// Every success-status decision sink (exit 0, HTTP 2xx), whatever field it
// reads, with the gate expression and the fields it names.
const SINK_PATTERNS = [
  ['exit', /process\.exit(?:Code\s*=\s*|\s*\(\s*)(.+)\?\s*0\b/],
  ['http', /\bsend\s*\(\s*res\s*,\s*(.+)\?\s*2\d\d\b/],
  ['py-exit', /(?:return\s+|sys\.exit\(\s*)0\s+if\s+(.+?)\s+else\b/],
  ['go-exit', /\bif\s+(.+?)\s*\{\s*code\s*=\s*0\s*\}/]
];

export function gateFields(gate) {
  const fields = new Set();
  const g = gate.replace(/===\s*true|!==\s*false/g, ' ');
  for (const m of g.matchAll(/\.get\(\s*['"]([\w$]+)['"]|(?:\?\.|\.)([A-Za-z_$][\w$]*)|\[\s*['"]([\w$]+)['"]\s*\]/g)) {
    fields.add(m[1] || m[2] || m[3]);
  }
  if (!fields.size) for (const m of g.matchAll(/[A-Za-z_$][\w$]*/g)) fields.add(m[0]);
  for (const noise of ['get', 'if', 'not', 'and', 'or', 'true', 'false', 'True', 'False', 'None', 'null', 'length']) fields.delete(noise);
  return [...fields].sort();
}

export function scanDecisionSinks(rel, source) {
  if (rel.startsWith('test/')) return [];
  const masked = maskFor(rel, source);
  const raw = source.split('\n');
  const out = [];
  masked.split('\n').forEach((line, index) => {
    for (const [kind, re] of SINK_PATTERNS) {
      if (kind === 'go-exit' && !rel.endsWith('.go')) continue;
      if (kind === 'py-exit' && !rel.endsWith('.py')) continue;
      if ((kind === 'exit' || kind === 'http') && rel.endsWith('.py')) continue;
      const m = line.match(re);
      if (!m) continue;
      const gate = m[1].replace(/^\(+/, '').trim();
      out.push({ file: rel, line: index + 1, code: raw[index].trim(), kind, gate, gate_fields: gateFields(gate) });
    }
  });
  return out;
}

export function scanSource(rel, source) {
  const ext = path.extname(rel);
  if (ext === '.go') return [];
  const masked = maskFor(rel, source);
  const rawLines = source.split('\n');
  const maskedLines = masked.split('\n');
  const reads = [];
  const res = ext === '.py' ? [PY_READ] : [JS_READ, JS_DESTRUCTURE];
  for (const re of res) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(masked))) {
      const line = lineOf(masked, m.index);
      reads.push({ file: rel, line, code: rawLines[line - 1].trim(),
        kind: re === JS_DESTRUCTURE ? 'destructure' : 'read' });
    }
  }
  // One entry per (line, kind); several reads on one line share a classification.
  const seen = new Set();
  const unique = reads.filter(r => { const k = `${r.line}:${r.kind}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => a.line - b.line);
  for (const r of unique) {
    r.positive_sinks = validOnlyPositiveSinks(maskedLines[r.line - 1]);
    r.valid_only_positive_sink = r.positive_sinks.length > 0;
    r.negated = /(?:!\s*\(?\s*[\w$][^\s&|;!]*?(?:\?\.|\.)valid\b|valid\s*(?:!==\s*true|===\s*false|!=\s*true)|\bnot\s+[\w$.\[\]'"]*valid|is\s+not\s+True)/.test(maskedLines[r.line - 1]) ||
      /valid['"]?\]?\s*(?:is not True|!==\s*true)/.test(maskedLines[r.line - 1]);
    r.explicit_on_line = EXPLICIT.test(maskedLines[r.line - 1].replace(/\bvalid\b/g, ''));
  }
  return unique;
}

export function scanRepository(base = root) {
  const findings = [];
  const sinks = [];
  for (const full of walk(base).sort()) {
    const rel = path.relative(base, full).split(path.sep).join('/');
    const isTest = rel.startsWith('test/');
    const source = fs.readFileSync(full, 'utf8');
    sinks.push(...scanDecisionSinks(rel, source));
    if (!/valid/.test(source)) continue;
    for (const r of scanSource(rel, source)) {
      if (isTest && !r.valid_only_positive_sink) continue;
      findings.push({ ...r, scope: isTest ? 'test' : 'shipped' });
    }
  }
  return { findings, sinks };
}

export const SINK_CATEGORIES = Object.freeze({
  'explicit-decision': 'success status requires an explicit decision field other than `valid`.',
  'conjunct': 'success status requires `valid` and an explicit decision field.',
  'validator-exit': 'exit status of a validator whose documented meaning is format/integrity validity only; it executes nothing.'
});

export function checkDecisionSinks(sinks, inventory) {
  const failures = [];
  if (!Array.isArray(inventory.decision_sinks)) return ['inventory decision_sinks missing'];
  const key = e => `${e.file}\u0000${e.line}\u0000${e.code}`;
  const byKey = new Map(inventory.decision_sinks.map(e => [key(e), e]));
  for (const sink of sinks) {
    const entry = byKey.get(key(sink));
    const where = `${sink.file}:${sink.line}`;
    if (!entry) { failures.push(`${where}: unclassified decision sink: ${sink.code}`); continue; }
    if (!Object.hasOwn(SINK_CATEGORIES, entry.category)) failures.push(`${where}: unknown sink category ${entry.category}`);
    if (typeof entry.effect !== 'string' || entry.effect.length < 8) failures.push(`${where}: effect missing`);
    const fields = sink.gate_fields;
    const aliasOfValid = entry.alias_of_valid === true;
    const validOnly = aliasOfValid || (fields.length > 0 && fields.every(f => f === 'valid'));
    if (validOnly && entry.category !== 'validator-exit') failures.push(`${where}: gate reads valid alone (${entry.category})`);
    if (entry.category === 'validator-exit' && !/^(bin|scripts|independent)\//.test(sink.file)) {
      failures.push(`${where}: validator-exit is limited to command-line validators`);
    }
    if (entry.category === 'validator-exit' && !validOnly) failures.push(`${where}: validator-exit used for a non-valid gate`);
    if (entry.category === 'conjunct' && !(fields.includes('valid') && fields.some(f => f !== 'valid'))) {
      failures.push(`${where}: conjunct gate must read valid and another decision field`);
    }
    if (entry.category === 'explicit-decision' && (fields.includes('valid') || validOnly)) {
      failures.push(`${where}: explicit-decision gate reads valid`);
    }
  }
  const found = new Set(sinks.map(key));
  for (const e of inventory.decision_sinks) if (!found.has(key(e))) failures.push(`${e.file}:${e.line}: stale decision sink entry: ${e.code}`);
  return failures;
}

export function checkInventory(findings, inventory, base = root) {
  const failures = [];
  if (!inventory || inventory.schema !== 'aml-valid-field-decision-inventory/1' || !Array.isArray(inventory.entries)) {
    return ['inventory schema invalid'];
  }
  const key = e => `${e.file}\u0000${e.line}\u0000${e.code}`;
  const byKey = new Map(inventory.entries.map(e => [key(e), e]));
  for (const f of findings) {
    const entry = byKey.get(key(f));
    if (!entry) { failures.push(`${f.file}:${f.line}: unclassified valid read: ${f.code}`); continue; }
    if (!Object.hasOwn(CATEGORIES, entry.category)) failures.push(`${f.file}:${f.line}: unknown category ${entry.category}`);
    if (typeof entry.effect !== 'string' || entry.effect.length < 8) failures.push(`${f.file}:${f.line}: effect missing`);
    // Exit and HTTP success sinks may read `valid` alone only in a validator
    // command; decision-named assignments never may. A positive `if` is
    // allowed only where the inventory states the counted verdict or the
    // other conjunct that the same branch requires.
    for (const sink of f.positive_sinks || []) {
      const reviewed = sink === 'if' && REVIEWED_POSITIVE_IF.some(r => r.file === f.file && r.code === f.code);
      const alias = sink === 'assign' && REVIEWED_VALIDATOR_ALIASES.some(r => r.file === f.file && r.code === f.code);
      const allowed = sink === 'assign' ? (alias ? ['validator-exit'] : []) : sink === 'if'
        ? (reviewed ? ['signed-verdict-count', 'conjunct'] : ['assertion']) : ['validator-exit'];
      if (!allowed.includes(entry.category)) {
        failures.push(`${f.file}:${f.line}: valid alone controls a positive ${sink} sink (${entry.category})`);
      }
    }
    if (entry.category === 'validator-exit' && !/^(bin|scripts|independent)\//.test(f.file)) {
      failures.push(`${f.file}:${f.line}: validator-exit is limited to command-line validators`);
    }
    if (entry.category === 'deny-guard' && !f.negated) failures.push(`${f.file}:${f.line}: deny-guard read is not negated`);
    if (entry.category === 'conjunct' && !f.explicit_on_line && !entry.conjunct_with) {
      failures.push(`${f.file}:${f.line}: conjunct without an explicit decision field (set conjunct_with)`);
    }
    if (entry.category === 'assertion' && !(f.scope === 'test' || /^scripts\/check-|^scripts\/run-|^scripts\/verify-/.test(f.file))) {
      failures.push(`${f.file}:${f.line}: assertion category outside tests/check scripts`);
    }
  }
  const found = new Set(findings.map(key));
  for (const e of inventory.entries) if (!found.has(key(e))) failures.push(`${e.file}:${e.line}: stale inventory entry: ${e.code}`);
  for (const sink of REQUIRED_DECISION_SINKS) {
    const file = path.join(base, sink.file);
    if (!fs.existsSync(file) || !fs.readFileSync(file, 'utf8').includes(sink.pattern)) {
      failures.push(`${sink.file}: required explicit decision sink missing (${sink.effect})`);
    }
  }
  return failures;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { findings, sinks } = scanRepository();
  let output;
  if (process.argv.includes('--scan')) {
    output = { findings, sinks };
  } else {
    const inventory = JSON.parse(fs.readFileSync(path.join(root, INVENTORY_PATH), 'utf8'));
    const failures = [...checkInventory(findings, inventory), ...checkDecisionSinks(sinks, inventory)];
    const count = (list, cats) => Object.fromEntries(Object.keys(cats).map(c => [c, list.filter(e => e.category === c).length]));
    output = {
      valid_reads: findings.length, valid_read_categories: count(inventory.entries || [], CATEGORIES),
      decision_sinks: sinks.length, decision_sink_categories: count(inventory.decision_sinks || [], SINK_CATEGORIES),
      failures
    };
    process.exitCode = failures.length ? 1 : 0;
  }
  // Let a piped stdout drain; exitCode (not exit) keeps buffered output.
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}
