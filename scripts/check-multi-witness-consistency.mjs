import fs from 'node:fs';
import crypto from 'node:crypto';

const contract = JSON.parse(fs.readFileSync('multi-witness-consistency-contract.json','utf8'));
const vectors = JSON.parse(fs.readFileSync('conformance/multi-witness/vectors.json','utf8'));
const sha256 = v => crypto.createHash('sha256').update(v).digest('hex');
const assert = (c,m) => { if (!c) throw new Error(m); };

function evaluate(receipts, minimumSequence) {
  const eligible = receipts.filter(r => r.trusted && !r.revoked);
  if (eligible.length < contract.quorum.minimum_distinct_trusted_witnesses) return false;
  if (new Set(eligible.map(r => r.witness_id)).size !== eligible.length) return false;
  if (new Set(eligible.map(r => r.fingerprint)).size !== eligible.length) return false;
  const roots = new Set(eligible.map(r => r.root));
  const sequences = new Set(eligible.map(r => r.sequence));
  if (roots.size !== 1 || sequences.size !== 1) return false;
  const sequence = eligible[0].sequence;
  if (sequence < minimumSequence) return false;
  return true;
}

for (const v of vectors.vectors) assert(evaluate(v.receipts, v.minimum_sequence) === v.accept, `Vector failed: ${v.id}`);

function pub(key) { return key.export({type:'spki',format:'pem'}); }
function fp(key) { return sha256(Buffer.from(pub(key))); }
function sign(body,key) { return crypto.sign(null,Buffer.from(JSON.stringify(body)),key).toString('base64'); }
function verify(body,sig,key) { return crypto.verify(null,Buffer.from(JSON.stringify(body)),key,Buffer.from(sig,'base64')); }

const checkpointRoot = sha256('synthetic-checkpoint-root');
const sequence = 7;
const witnesses = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];
const receipts = witnesses.map((w,i) => {
  const body = { protocol: contract.witness_receipt_protocol, checkpoint_root_sha256: checkpointRoot, checkpoint_sequence: sequence, witness_id: `synthetic-witness-${i+1}`, witness_public_key_pem: pub(w.publicKey), observation: 'synthetic_ci_reproduction', claim_boundary: contract.claim_boundary };
  return {...body, signature_base64: sign(body,w.privateKey)};
});
const trusted = new Set([fp(witnesses[0].publicKey), fp(witnesses[1].publicKey)]);
function normalize(receipt, revoked=new Set()) {
  const {signature_base64,...body}=receipt;
  const key=crypto.createPublicKey(body.witness_public_key_pem);
  const fingerprint=fp(key);
  return { witness_id:body.witness_id, fingerprint, trusted: trusted.has(fingerprint), revoked: revoked.has(fingerprint), sequence:body.checkpoint_sequence, root:body.checkpoint_root_sha256, signature_valid: verify(body,signature_base64,key) };
}
const normalized = receipts.map(r=>normalize(r)).filter(r=>r.signature_valid);
assert(evaluate(normalized, sequence) === true, 'Two trusted witnesses agreeing must satisfy quorum');
const split = receipts.slice(0,2).map(r=>normalize(r)); split[1].root='f'.repeat(64);
assert(evaluate(split, sequence) === false, 'Split view root must fail');
const duplicate=[normalized[0], {...normalized[0]}];
assert(evaluate(duplicate, sequence) === false, 'Duplicate receipt must not inflate quorum');
const revoked=new Set([fp(witnesses[1].publicKey)]);
assert(evaluate(receipts.slice(0,2).map(r=>normalize(r,revoked)),sequence) === false, 'Revoked witness must not count');
assert(evaluate(normalized, sequence+1) === false, 'Rollback below verifier minimum must fail');
const report={ protocol:contract.consistency_report_protocol, checkpoint_root_sha256:checkpointRoot, checkpoint_sequence:sequence, trusted_witness_quorum:contract.quorum.minimum_distinct_trusted_witnesses, vectors_checked:vectors.vectors.length, split_view_rejected:true, duplicate_quorum_inflation_rejected:true, revoked_witness_excluded:true, rollback_rejected:true, synthetic_witnesses_only:true, external_independent_witnesses_claimed:false, report_root_sha256:null, claim_boundary:contract.claim_boundary };
report.report_root_sha256=sha256(JSON.stringify({...report,report_root_sha256:null}));
fs.writeFileSync(process.argv[2] || 'aml-multi-witness-consistency-report.json', `${JSON.stringify(report,null,2)}\n`);
console.log(JSON.stringify(report,null,2));
