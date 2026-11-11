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
// those positive sinks as well.
//
// Before reads and sinks are matched, an alias pass rewrites names derived
// from `valid` to a synthetic `.valid` read: variables (`const ok = r.valid`),
// destructuring (`{ valid }`, `{ valid: x }`), object properties and
// Object.assign, subscripts (`r['valid']`), function and arrow-function
// returns, and functions imported from relative modules; derivation is
// transitive. Python uses an AST pass (scripts/valid_field_dataflow.py) with
// the same rules plus `from x import f`. Go is matched lexically.
// Not followed: values passed as call arguments or stored in containers,
// computed property names, non-relative imports, and expressions split over
// several lines. This is a static approximation, not a proof of data flow;
// see the inventory `method` field for its limits.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

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
  'consistency-status': 'selects only a non-authorization outcome: exit 3 (consistent, not authorized) versus failure, a diagnostic field, or a reviewed diagnostic exit.',
  'diagnostic-exit': 'read inside a reviewed --diagnostic-only branch whose output reports authorized:false and NOT AN AUTHORIZATION DECISION.',
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
    effect: 'worker verifier pass styling' },
  { file: 'runtime/commandAuthorization.js',
    pattern: 'const authorized = completeCommandAuthorization(result) && consistent;',
    effect: 'exit 0 for every JS verifier command that uses commandOutcome' },
  { file: 'bin/aml.js', pattern: ': result.authorized === true && result.authorization?.authorized === true ? 0',
    effect: 'exit 0 for aml verify-signed-quorum' },
  { file: 'independent/python/verify_witness.py', pattern: 'authorized = authorization["authorized"] is True and valid is True',
    effect: 'exit 0 for the Python witness verifier' },
  { file: 'independent/go/main.go', pattern: 'Authorized: false',
    effect: 'the Go witness verifier never authorizes' }
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
      // Keep identifier-like literals visible: `r['valid']` is a field read.
      if (!/^[A-Za-z_$][\w$]{0,63}$/.test(source.slice(i + 1, j))) blank(i + 1, Math.min(j, n));
      i = j + 1; prevSignificant = 'str'; continue;
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
// Exit-0 sinks that read `valid` (or an alias) inside an explicitly requested
// --diagnostic-only branch. Each must sit within ten lines after a guard
// naming the diagnostic mode; its output reports authorized:false and
// NOT AN AUTHORIZATION DECISION. Adding one requires changing this check.
export const REVIEWED_DIAGNOSTIC_EXITS = Object.freeze([
  { file: 'runtime/commandAuthorization.js', code: 'exitCode: consistent ? 0 : invalidCode',
    guard: 'if (diagnosticOnly) {', why: 'shared JS --diagnostic-only outcome' },
  { file: 'independent/python/verify_witness.py', code: 'return 0 if valid is True else 1',
    guard: 'if args.diagnostic_only:', why: 'Python witness verifier --diagnostic-only (conformance harness)' },
  { file: 'independent/python/wire_runtime.py', code: 'return 0 if consistent else 1',
    guard: 'if args.diagnostic_only:', why: 'Python wire runtime verify --diagnostic-only' },
  { file: 'independent/go/main.go', code: 'return out, 0',
    guard: 'if diagnostic {', why: 'Go witness verifier --diagnostic-only (conformance harness)' }
]);

export const REVIEWED_POSITIVE_IF = Object.freeze([
  { file: 'docs/aml-signed-verification-quorum.js', code: 'if (envelope.report.valid) {',
    why: 'counts an authenticated positive report toward threshold_met; authorized requires a held policy' },
  { file: 'docs/aml-signed-verification-quorum.js', code: 'if (signature.valid) {',
    why: 'preceded by `envelope?.report?.valid !== true || !allowed.has(fingerprint)) continue`; feeds the held-policy trusted set' },
  { file: 'independent/python/verify_signed_quorum.py', code: 'elif envelope["report"]["valid"]:',
    why: 'Python mirror of the signed-verdict count' }
]);

// ---------------------------------------------------------------------------
// Alias (data-flow) pass. A lexical scan of `x.valid` misses permission that
// flows through a variable, destructuring, a helper's return value, an
// object property, or an imported helper. Before sinks are matched, every
// use of a valid-derived name is rewritten to `__aml_alias.valid`, so the
// same sink rules see it. Derivation is transitive within a file; imported
// helpers are resolved across relative ES module imports, and Python uses
// its own AST (scripts/valid_field_dataflow.py). Expressions that also read
// an explicit decision field (see EXPLICIT) are not valid-only.
export const ALIAS_TOKEN = '__aml_alias.valid';
const READ_ATOM = String.raw`(?:[\w$][\w$.?\[\]]*?(?:\?\.|\.)valid\b|[\w$][\w$.?\]]*\[\s*['"]valid['"]\s*\]|[\w$][\w$.?\]]*\.get\(\s*['"]valid['"]\s*\))`;

function splitOperands(expr) {
  return expr.split(/&&|\|\||\band\b|\bor\b/).map(t => t.trim()).filter(Boolean);
}

// True when the expression is a positive use of valid-derived values only.
export function isValidOnlyExpression(expr, names = new Set(), functions = new Set()) {
  let e = String(expr).trim().replace(/;$/, '').trim();
  if (!e || EXPLICIT.test(e.replace(/\bvalid\b/g, ''))) return false;
  if (/\?[^.?]/.test(e.replace(/\?\./g, '.'))) return false; // ternaries are sinks, not aliases
  const ops = splitOperands(e);
  if (!ops.length) return false;
  let sawValid = false;
  for (let op of ops) {
    op = op.trim().replace(/^(?:Boolean|bool)\s*\(\s*(.*)\s*\)$/, '$1').replace(/^!!/, '')
      .replace(/^\(+|\)+$/g, '').trim()
      .replace(/^(?:Boolean|bool)\s*\(\s*(.*)\s*\)$/, '$1').replace(/^!!/, '')
      .replace(/\s*(?:===|==)\s*true$|\s*!==\s*false$|\s+is\s+True$/, '').replace(/^\(+|\)+$/g, '').trim();
    if (/^(?:true|True)$/.test(op)) continue;
    if (/^!|^not\b|!==|!=|===\s*false|is\s+not|==\s*False/.test(op)) return false;
    if (new RegExp(`^${READ_ATOM}$`).test(op) || op === ALIAS_TOKEN) { sawValid = true; continue; }
    if (/^[A-Za-z_$][\w$]*$/.test(op) && names.has(op)) { sawValid = true; continue; }
    const call = op.match(/^([A-Za-z_$][\w$.]*)\s*\(/);
    if (call && functions.has(call[1].split('.').pop()) && /\)$/.test(op)) { sawValid = true; continue; }
    return false;
  }
  return sawValid;
}

function functionBodies(masked) {
  // name -> body text for `function name(...) {...}` and `name = (...) => {...}` / `=> expr`.
  const out = [];
  const starts = /(?:\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*(\{)?)/g;
  let m;
  while ((m = starts.exec(masked))) {
    const name = m[1] || m[2];
    const braceAt = m[1] || m[3] ? masked.indexOf('{', m.index + m[0].length - 1) : -1;
    if (braceAt < 0) {
      const end = masked.indexOf('\n', starts.lastIndex);
      out.push({ name, returns: [masked.slice(starts.lastIndex, end < 0 ? undefined : end)] });
      continue;
    }
    let depth = 0; let j = braceAt;
    for (; j < masked.length; j += 1) {
      if (masked[j] === '{') depth += 1;
      else if (masked[j] === '}') { depth -= 1; if (depth === 0) break; }
    }
    const body = masked.slice(braceAt + 1, j);
    out.push({ name, returns: [...body.matchAll(/\breturn\s+([^;\n]+)/g)].map(r => r[1]) });
  }
  return out;
}

// Local valid-derived names, functions and object properties of one file.
export function deriveAliases(rel, masked, imported = { names: new Set(), functions: new Set() }) {
  const names = new Set(imported.names);
  const functions = new Set(imported.functions);
  const properties = new Set();
  if (rel.endsWith('.py') || rel.endsWith('.go')) return { names, functions, properties };
  const lines = masked.split('\n');
  for (let round = 0; round < 8; round += 1) {
    const before = names.size + functions.size + properties.size;
    for (const line of lines) {
      for (const m of line.matchAll(/(?:\b(?:const|let|var)\s+|^\s*|[;{(,]\s*)([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;]+)/g)) {
        if (isValidOnlyExpression(m[2], names, functions)) names.add(m[1]);
      }
      for (const m of line.matchAll(/\b(?:const|let|var)?\s*\{([^{}]*)\}\s*=(?!=)/g)) {
        for (const part of m[1].split(',')) {
          const d = part.trim().match(/^valid\s*(?::\s*([A-Za-z_$][\w$]*))?\s*(?:=.*)?$/);
          if (d) names.add(d[1] || 'valid');
        }
      }
      for (const m of line.matchAll(/(?:[{,]\s*|^\s*)([A-Za-z_$][\w$]*)\s*:\s*([^,}]+)/g)) {
        if (m[1] !== 'valid' && isValidOnlyExpression(m[2], names, functions)) properties.add(m[1]);
      }
      for (const m of line.matchAll(/\bObject\.assign\(\s*[^,]+,\s*\{\s*([A-Za-z_$][\w$]*)\s*:\s*([^}]+)\}/g)) {
        if (isValidOnlyExpression(m[2], names, functions)) properties.add(m[1]);
      }
    }
    for (const f of functionBodies(masked)) {
      if (f.returns.some(r => isValidOnlyExpression(r, names, functions))) functions.add(f.name);
    }
    if (names.size + functions.size + properties.size === before) break;
  }
  names.delete('valid_is_not_alias');
  return { names, functions, properties };
}

// Rewrite uses (not definitions) of valid-derived names to ALIAS_TOKEN.
const escapeRegExp = text => String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function applyAliases(maskedLine, aliases) {
  let line = maskedLine;
  for (const fn of aliases.functions) {
    line = line.replace(new RegExp(String.raw`(?<![\w$.])(?:[\w$]+\.)?${escapeRegExp(fn)}\s*\((?:[^()]|\([^()]*\))*\)`, 'g'),
      (m, offset, all) => /\bfunction\s*$/.test(all.slice(0, offset)) ? m : ALIAS_TOKEN);
  }
  for (const name of aliases.names) {
    line = line.replace(new RegExp(String.raw`(?<![\w$.])${escapeRegExp(name)}(?![\w$])(?!\s*=(?![=]))(?!\s*:(?!\s*[^,}]*\?))`, 'g'),
      (m, offset, all) => /\b(?:const|let|var|function)\s*[{\s]*$|[{,]\s*$/.test(all.slice(0, offset)) && /^\s*[,}=:]/.test(all.slice(offset + m.length)) ? m : ALIAS_TOKEN);
  }
  for (const prop of aliases.properties) {
    line = line.replace(new RegExp(String.raw`(?:\?\.|\.)${escapeRegExp(prop)}(?![\w$])(?!\s*=(?!=))`, 'g'), '.' + ALIAS_TOKEN);
    line = line.replace(new RegExp(String.raw`\[\s*(['"])${escapeRegExp(prop)}\1\s*\](?!\s*=(?!=))`, 'g'), '.' + ALIAS_TOKEN);
  }
  return line;
}

let pythonAliasCache = null;
// Python AST data-flow (names, functions, properties per file). Fails closed:
// if python3 is unavailable the check reports an error instead of passing.
export function pythonAliases(base, files) {
  if (pythonAliasCache && pythonAliasCache.base === base) return pythonAliasCache.map;
  const run = spawnSync('python3', [path.join(root, 'scripts/valid_field_dataflow.py'), base, ...files], { encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`python data-flow pass failed: ${run.stderr || run.status}`);
  const map = JSON.parse(run.stdout);
  pythonAliasCache = { base, map };
  return map;
}

export function pythonAliasesForSource(rel, source) {
  const run = spawnSync('python3', [path.join(root, 'scripts/valid_field_dataflow.py'), '--stdin', rel],
    { input: source, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`python data-flow pass failed: ${run.stderr || run.status}`);
  return JSON.parse(run.stdout)[rel];
}

function toAliasSets(entry) {
  return { names: new Set(entry?.names || []), functions: new Set(entry?.functions || []),
    properties: new Set(entry?.properties || []) };
}

// Aliases for one file: Python from the AST pass, JS/HTML from deriveAliases.
export function aliasesFor(rel, source, context = {}) {
  if (rel.endsWith('.go')) return { names: new Set(), functions: new Set(), properties: new Set() };
  if (rel.endsWith('.py')) return toAliasSets(context.python ? context.python[rel] : pythonAliasesForSource(rel, source));
  const imported = context.exportedFunctions ? resolveImports(rel, source, context.exportedFunctions)
    : { names: new Set(), functions: new Set() };
  return deriveAliases(rel, maskFor(rel, source), imported);
}

function resolveImports(rel, source, exportedFunctions) {
  const masked = source;
  const functions = new Set();
  const names = new Set();
  for (const m of masked.matchAll(/\bimport\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g)) {
    if (!m[2].startsWith('.')) continue;
    const target = path.posix.normalize(path.posix.join(path.posix.dirname(rel), m[2]));
    const exported = exportedFunctions.get(target);
    if (!exported) continue;
    for (const part of m[1].split(',')) {
      const [orig, local] = part.trim().split(/\s+as\s+/);
      if (orig && exported.has(orig.trim())) functions.add((local || orig).trim());
    }
  }
  return { names, functions };
}

function maskFor(rel, source) {
  const ext = path.extname(rel);
  return ext === '.py' ? maskPython(source) : ext === '.html' ? htmlScripts(source) : maskJavaScript(source);
}

// Every success-status decision sink (exit 0, HTTP 2xx), whatever field it
// reads, with the gate expression and the fields it names.
// Success outcomes: exit 0 (direct, inverted `cond ? 1 : 0`, via a computed
// code value, or any `cond ? 0 : N` exit-code expression) and HTTP 2xx.
const SINK_PATTERNS = [
  ['exit', /process\.exit(?:Code\s*=\s*|\s*\(\s*)(.+)\?\s*0\b/],
  ['exit-inverted', /process\.exit(?:Code\s*=\s*|\s*\(\s*)(.+)\?\s*[1-9]\d*\s*:\s*0\b/],
  ['exit-code-value', /(?:^|[^\w$.])(?:exitCode|exit_code|code|status)\s*[:=]\s*(?!=)(.+?)\?\s*0\s*:/],
  ['zero-ternary', /(?:^|[=(,:]\s*|return\s+)((?:[^(,:?=!]|[=!]={1,2}(?!=)|!(?!=))+?)\?\s*0\s*:\s*[1-9]\d*\b/],
  ['http', /\bsend\s*\(\s*res\s*,\s*(.+)\?\s*2\d\d\b/],
  // A failure exit set only when a gate is false leaves success implicit.
  ['exit-implicit', /\bif\s*\(\s*!\s*(.+?)\)\s*\{?\s*process\.exit(?:Code\s*=\s*|\s*\(\s*)[1-9]/],
  ['py-exit-implicit', /\bif\s+not\s+(.+?):\s*(?:return|sys\.exit\(|raise\s+SystemExit\()\s*[1-9]/],
  ['http-status', /(?:statusCode\s*=|writeHead\s*\(|\.status\s*\()\s*(.+?)\?\s*2\d\d\b/],
  ['py-exit', /(?:return\s+|sys\.exit\(\s*|SystemExit\(\s*)0\s+if\s+(.+?)\s+else\b/],
  ['py-exit-inverted', /(?:return\s+|sys\.exit\(\s*|SystemExit\(\s*)[1-9]\d*\s+if\s+(.+?)\s+else\s+0\b/],
  ['go-exit', /\bif\s+(.+?)\s*\{\s*code\s*=\s*0\s*\}/],
  ['go-return-zero', /^\s*(?:return\s+[\w.]+\s*,\s*0|os\.Exit\(\s*0\s*\)|code\s*=\s*0)\s*$/]
];

export function gateFields(gate) {
  const fields = new Set();
  const g = gate.replace(/===\s*true|!==\s*false/g, ' ');
  for (const m of g.matchAll(/\.get\(\s*['"]([\w$]+)['"]|(?:\?\.|\.)([A-Za-z_$][\w$]*)|\[\s*['"]([\w$]+)['"]\s*\]/g)) {
    fields.add(m[1] || m[2] || m[3]);
  }
  if (!fields.size) for (const m of g.matchAll(/[A-Za-z_$][\w$]*/g)) fields.add(m[0]);
  for (const noise of ['get', 'if', 'not', 'and', 'or', 'true', 'false', 'True', 'False', 'None', 'null', 'length', 'is']) fields.delete(noise);
  if (fields.has('Valid')) { fields.delete('Valid'); fields.add('valid'); }
  return [...fields].sort();
}

export function scanDecisionSinks(rel, source, aliases = aliasesFor(rel, source)) {
  if (rel.startsWith('test/')) return [];
  const masked = maskFor(rel, source).split('\n').map(line => applyAliases(line, aliases)).join('\n');
  const raw = source.split('\n');
  const out = [];
  masked.split('\n').forEach((line, index) => {
    for (const [kind, re] of SINK_PATTERNS) {
      const go = kind.startsWith('go-');
      const py = kind.startsWith('py-');
      if (go !== rel.endsWith('.go')) continue;
      if (py && !rel.endsWith('.py')) continue;
      if (!py && !go && rel.endsWith('.py') && kind !== 'zero-ternary') continue;
      if (kind === 'zero-ternary' && rel.endsWith('.py')) continue;
      const allLines = masked.split('\n');
      // Implicit-success guards may put the exit on the next line.
      const probe = kind.endsWith('-implicit') && /\{\s*$|:\s*$/.test(line)
        ? `${line} ${allLines[index + 1] ?? ''}` : line;
      const m = probe.match(re);
      if (!m) continue;
      let gate = (m[1] ?? '').replace(/^\(+/, '').trim();
      if (kind === 'go-return-zero') {
        // The gate is the nearest enclosing `if` condition above (by indentation).
        const indent = line.match(/^\s*/)[0].length;
        const lines = masked.split('\n');
        for (let k = index - 1; k >= 0; k -= 1) {
          const c = lines[k].match(/^(\s*)(?:\}\s*else\s+)?if\s+(.+?)\s*\{\s*$/);
          if (c && c[1].length < indent) { gate = c[2]; break; }
          if (/^\S/.test(lines[k])) break;
        }
        if (!gate) gate = 'unconditional';
      }
      out.push({ file: rel, line: index + 1, code: raw[index].trim(), kind, gate, gate_fields: gateFields(gate) });
    }
  });
  return out;
}

export function scanSource(rel, source, aliases = aliasesFor(rel, source)) {
  const ext = path.extname(rel);
  if (ext === '.go') return [];
  const masked = maskFor(rel, source).split('\n').map(line => applyAliases(line, aliases)).join('\n');
  const rawLines = source.split('\n');
  const maskedLines = masked.split('\n');
  const reads = [];
  const res = ext === '.py' ? [PY_READ] : [JS_READ, JS_DESTRUCTURE];
  for (const re of res) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(masked))) {
      const line = lineOf(masked, m.index);
      const aliasUse = masked.slice(m.index - ALIAS_TOKEN.length + 6, m.index + 6) === ALIAS_TOKEN ||
        masked.slice(Math.max(0, m.index - 14), m.index + 6).endsWith(ALIAS_TOKEN);
      reads.push({ file: rel, line, code: rawLines[line - 1].trim(),
        kind: re === JS_DESTRUCTURE ? 'destructure' : aliasUse ? 'alias' : 'read' });
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
  const files = walk(base).sort().map(full => ({ full, rel: path.relative(base, full).split(path.sep).join('/') }));
  const sources = new Map(files.map(f => [f.rel, fs.readFileSync(f.full, 'utf8')]));
  const python = pythonAliases(base, files.filter(f => f.rel.endsWith('.py')).map(f => f.rel));
  // Exported valid-derived helpers, for cross-module import resolution.
  const exportedFunctions = new Map();
  for (const { rel } of files) {
    if (rel.endsWith('.py') || rel.endsWith('.go')) continue;
    const local = deriveAliases(rel, maskFor(rel, sources.get(rel)));
    if (local.functions.size) exportedFunctions.set(rel, local.functions);
  }
  const context = { python, exportedFunctions };
  const aliasSummary = [];
  for (const { rel } of files) {
    const isTest = rel.startsWith('test/');
    const source = sources.get(rel);
    const aliases = aliasesFor(rel, source, context);
    if (aliases.names.size || aliases.functions.size || aliases.properties.size) {
      aliasSummary.push({ file: rel, names: [...aliases.names].sort(), functions: [...aliases.functions].sort(),
        properties: [...aliases.properties].sort() });
    }
    sinks.push(...scanDecisionSinks(rel, source, aliases));
    if (!/valid/.test(source) && !(aliases.names.size || aliases.functions.size || aliases.properties.size)) continue;
    for (const r of scanSource(rel, source, aliases)) {
      if (isTest && !r.valid_only_positive_sink) continue;
      findings.push({ ...r, scope: isTest ? 'test' : 'shipped' });
    }
  }
  return { findings, sinks, aliases: aliasSummary };
}

export const SINK_CATEGORIES = Object.freeze({
  'explicit-decision': 'success status requires an explicit decision field other than `valid`.',
  'conjunct': 'success status requires `valid` and an explicit decision field.',
  'diagnostic-exit': 'exit 0 in a reviewed --diagnostic-only branch (REVIEWED_DIAGNOSTIC_EXITS); output reports authorized:false and NOT AN AUTHORIZATION DECISION.',
  'non-decision': 'a zero/non-zero value that is not an authorization outcome (count, index, sort key); it gates nothing.'
});

function diagnosticGuarded(base, file, line, guard) {
  try {
    const lines = fs.readFileSync(path.join(base, file), 'utf8').split('\n');
    for (let k = Math.max(0, line - 11); k < line - 1; k += 1) if (lines[k].trim() === guard) return true;
  } catch {}
  return false;
}

export function checkDecisionSinks(sinks, inventory, base = root) {
  const failures = [];
  if (!Array.isArray(inventory.decision_sinks)) return ['inventory decision_sinks missing'];
  const key = e => `${e.file}\u0000${e.line}\u0000${e.code}`;
  const byKey = new Map(inventory.decision_sinks.map(e => [key(e), e]));
  // Several sink patterns can match one line; judge the line on the union
  // of every gate field read there.
  const merged = new Map();
  for (const sink of sinks) {
    const prior = merged.get(key(sink));
    merged.set(key(sink), prior ? { ...prior, kind: `${prior.kind}+${sink.kind}`,
      gate_fields: [...new Set([...prior.gate_fields, ...sink.gate_fields])].sort() } : sink);
  }
  for (const sink of merged.values()) {
    const entry = byKey.get(key(sink));
    const where = `${sink.file}:${sink.line}`;
    if (!entry) { failures.push(`${where}: unclassified decision sink: ${sink.code}`); continue; }
    if (!Object.hasOwn(SINK_CATEGORIES, entry.category)) failures.push(`${where}: unknown sink category ${entry.category}`);
    if (typeof entry.effect !== 'string' || entry.effect.length < 8) failures.push(`${where}: effect missing`);
    const fields = sink.gate_fields;
    const validOnly = fields.length > 0 && fields.every(f => f === 'valid');
    const reviewed = REVIEWED_DIAGNOSTIC_EXITS.find(r => r.file === sink.file && r.code === sink.code);
    if (entry.category === 'diagnostic-exit') {
      if (!reviewed) failures.push(`${where}: diagnostic-exit not in REVIEWED_DIAGNOSTIC_EXITS`);
      else if (!diagnosticGuarded(base, sink.file, sink.line, reviewed.guard)) failures.push(`${where}: diagnostic-exit without its guard`);
    } else if (validOnly) failures.push(`${where}: gate reads valid alone (${entry.category})`);
    if (entry.category === 'non-decision' && (fields.includes('valid') || /process\.exit|send\s*\(|statusCode|writeHead|sys\.exit|SystemExit|exitCode|os\.Exit/.test(sink.code))) {
      failures.push(`${where}: non-decision used for an exit/HTTP sink or a valid gate`);
    }
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
      const diagnostic = REVIEWED_DIAGNOSTIC_EXITS.some(r => r.file === f.file && r.code === f.code);
      const allowed = sink === 'assign' ? [] : sink === 'if'
        ? (reviewed ? ['signed-verdict-count', 'conjunct'] : ['assertion'])
        : diagnostic ? ['diagnostic-exit'] : [];
      if (!allowed.includes(entry.category)) {
        failures.push(`${f.file}:${f.line}: valid alone controls a positive ${sink} sink (${entry.category})`);
      }
    }
    if (entry.category === 'consistency-status' && !/^(bin|scripts|independent|runtime\/commandAuthorization\.js)/.test(f.file)) {
      failures.push(`${f.file}:${f.line}: consistency-status is limited to command-line outcome code`);
    }
    if (entry.category === 'diagnostic-exit' && !REVIEWED_DIAGNOSTIC_EXITS.some(r => r.file === f.file && r.code === f.code)) {
      failures.push(`${f.file}:${f.line}: diagnostic-exit read not in REVIEWED_DIAGNOSTIC_EXITS`);
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
    const scan = scanRepository();
    output = { findings: scan.findings, sinks: scan.sinks, aliases: scan.aliases };
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
