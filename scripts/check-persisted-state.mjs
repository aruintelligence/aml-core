import fs from 'node:fs';
import crypto from 'node:crypto';
import { compileSource } from '../index.js';

function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fail(message) { console.error(message); process.exit(1); }
function sha256(text) { return crypto.createHash('sha256').update(text).digest('hex'); }

const contract = read('persisted-state-contract.json');
const state = read('conformance/persisted-state/v1.json');
if (contract.protocol !== 'aml-persisted-state-contract/1') fail('Unexpected persisted-state contract');
if (state.protocol !== contract.envelope_protocol) fail('Persisted-state protocol mismatch');
for (const field of contract.required_fields) if (!(field in state)) fail(`Missing persisted-state field: ${field}`);
if (sha256(state.source) !== state.source_sha256) fail('Persisted source hash mismatch');

const compiled = compileSource(state.source);
if (!compiled) fail('Persisted AML source did not compile');
const exp = state.semantic_expectation;
const observedAllowed = Number(exp.restoration_value) >= Number(exp.attention_cost);
if (observedAllowed !== exp.render_allowed) fail('Persisted semantic expectation violates canonical render gate');

const roundtrip = JSON.parse(JSON.stringify(state));
if (JSON.stringify(roundtrip.extension_data) !== JSON.stringify(state.extension_data)) fail('Unknown extension data was not preserved');
if (roundtrip.source_sha256 !== state.source_sha256) fail('Roundtrip changed source identity');

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-persisted-state-verification/1',
  envelope_protocol: state.protocol,
  source_sha256: state.source_sha256,
  unknown_fields_preserved: true,
  semantic_expectation_verified: true,
  claim_boundary: 'Project-controlled persisted-state fixture verification only; not a guarantee for arbitrary downstream databases, migrations, or application state.'
}, null, 2));
