import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const limits = JSON.parse(fs.readFileSync('resource-limits.json', 'utf8')).deterministic_fuzz;
const base = `transmission "fuzz" {
  engram card {
    value: "Deterministic fuzz baseline"
    purpose: "exercise parser and compiler robustness"
    memory_role: "diagnostic"
    user_effect: "clarity"
    attention_cost: 1
    restoration_value: 2
  }
}`;

let state = 0x41c6ce57;
function rand() {
  state ^= state << 13; state >>>= 0;
  state ^= state >>> 17; state >>>= 0;
  state ^= state << 5; state >>>= 0;
  return state / 0x100000000;
}
function pick(n) { return Math.floor(rand() * Math.max(1, n)); }

const corpus = [
  '', '\0', '{', '}', 'transmission', 'transmission "x" {',
  'transmission "x" { engram y { attention_cost: -1 } }',
  'transmission "x" { engram y { attention_cost: NaN restoration_value: Infinity } }',
  'transmission "💥" { engram ü { value: "\u2028\u2029" } }',
  base.repeat(4), base.slice(0, Math.floor(base.length / 2))
];

const inserts = ['{','}','[',']','"','\\','\n','\t','💥','\0','attention_cost: 999999999','restoration_value: -999999999'];
for (let i = 0; i < 48; i++) {
  let s = base;
  const op = i % 6;
  if (op === 0 && s.length) {
    const at = pick(s.length); s = s.slice(0, at) + s.slice(at + 1);
  } else if (op === 1) {
    const at = pick(s.length + 1); const token = inserts[pick(inserts.length)]; s = s.slice(0, at) + token + s.slice(at);
  } else if (op === 2 && s.length) {
    const at = pick(s.length); const token = inserts[pick(inserts.length)]; s = s.slice(0, at) + token + s.slice(at + 1);
  } else if (op === 3) {
    const start = pick(s.length); const end = Math.min(s.length, start + 1 + pick(24)); s = s.slice(0, start) + s.slice(start, end).repeat(2) + s.slice(end);
  } else if (op === 4) {
    s = s.slice(0, pick(s.length + 1));
  } else {
    s = `${s}\n${inserts[pick(inserts.length)]}`;
  }
  corpus.push(s);
}

let accepted = 0;
let rejected = 0;
for (let i = 0; i < corpus.length; i++) {
  const source = corpus[i];
  if (Buffer.byteLength(source, 'utf8') > limits.max_case_bytes) throw new Error(`Corpus case ${i} exceeded size bound`);
  const encoded = Buffer.from(source).toString('base64');
  const run = spawnSync(process.execPath, ['scripts/aml-fuzz-worker.mjs', encoded], {
    encoding: 'utf8',
    timeout: limits.per_case_timeout_ms,
    maxBuffer: limits.max_worker_output_bytes
  });
  if (run.error?.code === 'ETIMEDOUT') throw new Error(`Fuzz case ${i} exceeded ${limits.per_case_timeout_ms}ms execution bound`);
  if (run.status !== 0) throw new Error(`Fuzz case ${i} failed worker contract: status=${run.status} stderr=${run.stderr}`);
  const report = JSON.parse(run.stdout);
  if (!report.deterministic) throw new Error(`Fuzz case ${i} produced nondeterministic result`);
  if (report.outcome.kind === 'accepted') accepted++; else rejected++;
}

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-deterministic-fuzz-report/1',
  seed: '0x41c6ce57',
  cases: corpus.length,
  accepted,
  rejected,
  per_case_timeout_ms: limits.per_case_timeout_ms,
  max_case_bytes: limits.max_case_bytes,
  max_worker_output_bytes: limits.max_worker_output_bytes,
  claim_boundary: 'Deterministic bounded project fuzz regression only; not proof of absence of vulnerabilities or an independent security audit.'
}, null, 2));
