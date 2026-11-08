import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createProviderExecutionState } from "../pilots/action-boundary/provider-execution-state.mjs";
import { verifyProviderStatus, verifyProviderHistory } from "../pilots/action-boundary/verify-provider-status.mjs";

const root = fileURLToPath(new URL("../pilots/action-boundary/", import.meta.url));
const provider = path.join(root, "atomic-authorized-provider-fixture.py");
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const DESTINATION = "fixture:atomic";
const EFFECT = "record:simulated";

// Separate AML-AUTHORIZED-EXECUTION/1 profile: Python ensure_ascii=True,
// not core sorted-json-v1. Its flat fields use ASCII keys and safe JS integers.
function canonicalAuthorization(statement) {
  const ordered = Object.fromEntries(Object.keys(statement).sort().map(key => {
    const value = statement[key];
    assert.ok(typeof value === "string" || Number.isSafeInteger(value), "authorization signer requires strings or safe integers");
    return [key, value];
  }));
  return JSON.stringify(ordered).replace(/[\u007f-\uffff]/g,
    character => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
}

function python(args, input = "") {
  const result = spawnSync("python3", args, { input, encoding: "utf8", timeout: 20_000 });
  assert.ifError(result.error);
  return result;
}

async function scenario(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-atomic-auth-"));
  try {
    const database = path.join(directory, "provider.sqlite");
    const issuerFile = path.join(directory, "issuer-public.pem");
    const issuer = crypto.generateKeyPairSync("ed25519");
    fs.writeFileSync(issuerFile, issuer.publicKey.export({ type: "spki", format: "pem" }));
    const statusKeys = crypto.generateKeyPairSync("ed25519");
    const statusPrivate = path.join(directory, "status-private.pem");
    fs.writeFileSync(statusPrivate, statusKeys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const init = python([provider, database, "initialize", issuerFile]);
    assert.equal(init.status, 0, init.stderr);
    const request = { operation_id: crypto.randomUUID(), destination: DESTINATION,
      effect: EFFECT, body: { value: "synthetic local record" } };
    const sign = (authorization, key = issuer.privateKey) => crypto.sign(null, Buffer.concat([
      Buffer.from("AML-AUTHORIZED-EXECUTION/1\0"), Buffer.from(canonicalAuthorization(authorization))
    ]), key).toString("base64");
    const signGeneric = authorization => crypto.sign(null, Buffer.concat([
      Buffer.from("AML-AUTHORIZED-EXECUTION/1\0"), Buffer.from(canonicalJSONStringify(authorization))
    ]), issuer.privateKey).toString("base64");
    const envelopeFor = (value = request, changes = {}, bytes = JSON.stringify(value)) => {
      const authorization = { version: "aml-authorized-execution/1", issuer: "test-issuer", principal: "test-principal",
        policy_id: "test-policy", policy_epoch: 1, operation_id: value.operation_id, request_sha256: sha(bytes),
        destination: value.destination, effect: value.effect, expires_at_ms: Date.now() + 120_000, ...changes };
      return { authorization, signature: sign(authorization), request_bytes: bytes };
    };
    const envelope = envelopeFor();
    const send = (value = envelope, fault = null, key = issuerFile) => python([
      provider, database, "request", key, ...(fault ? [`--fault=${fault}`] : [])
    ], typeof value === "string" ? value : JSON.stringify(value));
    const expected = (value = envelope) => ({ operation_id: value.authorization.operation_id,
      request_sha256: value.authorization.request_sha256, destination: value.authorization.destination });
    const readStatus = (value = expected()) => python([provider, database, "status"], JSON.stringify(value));
    const admin = (code, ...args) => python(["-c", `import sys; sys.path.insert(0,sys.argv[1]); ${code}`, root, database, ...args]);
    // Evaluator-owned persisted observations, not fixture-reported counters.
    const snapshot = () => {
      const result = admin("import sqlite3,json; from sqlite_path import sqlite_file_uri; c=sqlite3.connect(sqlite_file_uri(sys.argv[2],'ro'),uri=True); " +
        "print(json.dumps({'claims':c.execute('SELECT operation_id,request_sha256 FROM claims ORDER BY operation_id').fetchall()," +
        "'effects':c.execute('SELECT operation_id,request_sha256,destination,effect_id FROM effects ORDER BY operation_id').fetchall()}))");
      assert.equal(result.status, 0, result.stderr);
      return JSON.parse(result.stdout);
    };
    const assertEmpty = () => assert.deepEqual(snapshot(), { claims: [], effects: [] });
    const assertPair = (value = envelope) => {
      const rows = snapshot();
      assert.deepEqual(rows.claims, [[value.authorization.operation_id, sha(value.request_bytes)]]);
      assert.equal(rows.effects.length, 1);
      assert.deepEqual(rows.effects[0].slice(0, 3), [value.authorization.operation_id, sha(value.request_bytes), value.authorization.destination]);
      assert.match(rows.effects[0][3], /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
      return rows.effects[0][3];
    };
    const signedStatus = (challenge = crypto.randomBytes(32).toString("hex")) => {
      const result = spawnSync(process.execPath, [path.join(root, "signed-provider-status.mjs"), database, statusPrivate, challenge],
        { input: request.operation_id, encoding: "utf8", timeout: 20_000 });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      return { envelope: JSON.parse(result.stdout), challenge };
    };
    await run({ database, directory, issuerFile, request, sign, signGeneric, envelopeFor, envelope, send,
      expected, readStatus, admin, snapshot, assertEmpty, assertPair, signedStatus, statusKeys });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

const reject = (result, reason) => {
  assert.equal(result.status, 2, result.stderr);
  if (reason) assert.match(result.stderr, reason);
};

// Existing legacy tests exercise the old API and its preserved two-DB failures.
test("atomic authorized provider persists a bound claim/effect pair, not a second dispatch", () => scenario(s => {
  const first = s.send();
  assert.equal(first.status, 0, first.stderr);
  assert.equal(JSON.parse(first.stdout).effect_id, s.assertPair());
  reject(s.send(), /authorization_spent/);
  assert.equal(s.assertPair(), JSON.parse(first.stdout).effect_id);
}));

test("transaction helper refuses autocommit and does not reserve a claim", () => scenario(s => {
  const input = path.join(s.directory, "input.json");
  fs.writeFileSync(input, JSON.stringify(s.envelope));
  const result = s.admin("import sqlite3,json; from authorized_execution import consume_in_transaction; " +
    "e=json.load(open(sys.argv[4])); c=sqlite3.connect(sys.argv[2],isolation_level=None); " +
    "consume_in_transaction(c,sys.argv[3],e['authorization'],e['signature'],e['request_bytes'].encode())", s.issuerFile, input);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /authorization_transaction_required/);
  s.assertEmpty();
}));

test("transaction helper leaves commit/rollback to its caller", () => scenario(s => {
  const input = path.join(s.directory, "input.json");
  fs.writeFileSync(input, JSON.stringify(s.envelope));
  const result = s.admin("import sqlite3,json; from authorized_execution import consume_in_transaction; " +
    "e=json.load(open(sys.argv[4])); c=sqlite3.connect(sys.argv[2],isolation_level=None); c.execute('BEGIN IMMEDIATE'); " +
    "r=consume_in_transaction(c,sys.argv[3],e['authorization'],e['signature'],e['request_bytes'].encode()); " +
    "assert c.in_transaction; assert c.execute('SELECT count(*) FROM claims').fetchone()[0]==1; " +
    "from sqlite_path import sqlite_file_uri; observer=sqlite3.connect(sqlite_file_uri(sys.argv[2],'ro'),uri=True); " +
    "assert observer.execute('SELECT count(*) FROM claims').fetchone()[0]==0; observer.close(); " +
    "c.execute('ROLLBACK'); assert not c.in_transaction; print(r['operation_id'])", s.issuerFile, input);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), s.request.operation_id);
  s.assertEmpty();
  assert.equal(s.send().status, 0);
  s.assertPair();
}));

for (const [fault, exit] of Object.entries({ before_claim: 80, after_claim: 81, after_effect: 82, before_commit: 83, after_commit: 84 })) {
  test(`abrupt crash ${fault}: persisted pair and terminal recovery are truthful`, () => scenario(s => {
    const result = s.send(s.envelope, fault);
    assert.equal(result.status, exit, result.stderr);
    assert.equal(result.stdout, "", "crash must not claim success");
    const recovered = s.readStatus(); // fresh provider process: opens SQLite and recovers hot journals
    assert.equal(recovered.status, 0, recovered.stderr);
    const status = JSON.parse(recovered.stdout);
    assert.equal(status.independent_confirmation, false);
    if (fault === "after_commit") {
      assert.equal(status.result, "PROVIDER_REPORTED");
      assert.equal(status.record.effect_id, s.assertPair());
      reject(s.send(), /authorization_spent/);
      assert.equal(status.record.effect_id, s.assertPair());
    } else {
      assert.equal(status.result, "INCOMPLETE", "absence is not independent evidence of failure/no earlier effect");
      assert.equal(status.record, null);
      s.assertEmpty();
      // Explicit test invocation, not an automatic retry decision by status().
      assert.equal(s.send().status, 0);
      s.assertPair();
    }
  }));
}

test("lost acknowledgment uses existing signed verification and state reducer without independent-confirmation rewrite", () => scenario(s => {
  const state = createProviderExecutionState({ operationId: s.request.operation_id, proposalSha256: "a".repeat(64) });
  state.record("approved", "test:synthetic-approval");
  state.record("grant_consumed", "test:attempt");
  state.record("request_initiated", s.envelope.authorization.request_sha256);
  assert.equal(s.send(s.envelope, "after_commit").status, 84);
  state.record("outcome_uncertain", "test:lost-ack");
  const before = s.snapshot();
  const signed = s.signedStatus();
  assert.equal(verifyProviderStatus(signed.envelope, { publicKey: s.statusKeys.publicKey.export({ type: "spki", format: "pem" }),
    operationId: s.request.operation_id, requestSha256: sha(s.envelope.request_bytes), destination: DESTINATION,
    challenge: signed.challenge }), "PROVIDER_REPORTED");
  state.record("provider_accepted", "test:signed-provider-status");
  state.record("completed", "test:provider-row-reported");
  assert.equal(state.snapshot().state, "completed");
  assert.equal(JSON.parse(s.readStatus().stdout).independent_confirmation, false);
  assert.deepEqual(s.snapshot(), before, "verification and recovery must not write history");
}));

test("forged or mutated exact requests leave neither claim nor effect", () => scenario(s => {
  const mutations = [
    { ...s.envelope, signature: "AAAA" },
    { ...s.envelope, authorization: { ...s.envelope.authorization, principal: "forged" } },
    { ...s.envelope, request_bytes: JSON.stringify({ ...s.request, body: { value: "changed" } }) },
    { ...s.envelope, request_bytes: JSON.stringify({ ...s.request, destination: "fixture:other" }) },
    { ...s.envelope, request_bytes: JSON.stringify({ ...s.request, effect: "remote:payment" }) },
    { ...s.envelope, request_bytes: JSON.stringify({ ...s.request, operation_id: crypto.randomUUID() }) },
    s.envelopeFor(s.request, { destination: "fixture:other" }),
    s.envelopeFor(s.request, { operation_id: crypto.randomUUID() })
  ];
  for (const mutation of mutations) {
    reject(s.send(mutation));
    s.assertEmpty();
  }
  assert.equal(s.send().status, 0);
  s.assertPair();
}));

test("fixed effect validation after consumption rolls back its provisional claim", () => scenario(s => {
  for (const request of [
    { ...s.request, effect: "sql:execute" },
    { ...s.request, destination: "https://not-a-provider.invalid" },
    { ...s.request, body: { sql: "DROP TABLE effects" } },
    { ...s.request, body: { value: "x".repeat(1025) } }
  ]) {
    reject(s.send(s.envelopeFor(request)), /unsupported_fixture_effect/);
    s.assertEmpty();
  }
  const unicode = s.envelopeFor({ ...s.request, body: { value: "ĀML synthetic" } });
  assert.equal(s.send(unicode).status, 0);
  s.assertPair(unicode);
}));

test("duplicate keys, constants, invalid shapes and caller-supplied failpoints cannot reserve authority", () => scenario(s => {
  const bytes = s.envelope.request_bytes.replace('"body":', '"destination":"fixture:atomic","body":');
  reject(s.send(s.envelopeFor(s.request, {}, bytes)), /duplicate_input_key/);
  const nonfinite = s.envelope.request_bytes.replace('"synthetic local record"', 'NaN');
  reject(s.send(s.envelopeFor(s.request, {}, nonfinite)), /nonfinite_input/);
  reject(s.send({ ...s.envelope, fault: "after_commit" }), /invalid_envelope/);
  reject(s.send(JSON.stringify(s.envelope).replace('"signature":', '"request_bytes":"{}","signature":')), /duplicate_input_key/);
  reject(s.send({ ...s.envelope, request_bytes: "[]" }));
  reject(s.send(" ".repeat(65537)), /oversized_input/);
  s.assertEmpty();
}));

test("expired authorization creates no persisted effect or claim", () => scenario(s => {
  reject(s.send(s.envelopeFor(s.request, { expires_at_ms: Date.now() - 1 })), /authorization_expired/);
  s.assertEmpty();
}));

test("prior revocation rejects atomically, while post-commit revocation does not undo history", () => scenario(s => {
  const other = { ...s.request, operation_id: crypto.randomUUID() };
  const revoked = s.admin("from authorized_execution import revoke; revoke(sys.argv[2],sys.argv[3])", other.operation_id);
  assert.equal(revoked.status, 0, revoked.stderr);
  reject(s.send(s.envelopeFor(other)), /authorization_revoked/);
  s.assertEmpty();
  assert.equal(s.send().status, 0);
  const before = s.snapshot();
  assert.equal(s.admin("from authorized_execution import revoke; revoke(sys.argv[2],sys.argv[3])", s.request.operation_id).status, 0);
  reject(s.send(), /authorization_revoked/);
  assert.equal(JSON.parse(s.readStatus().stdout).result, "PROVIDER_REPORTED");
  assert.deepEqual(s.snapshot(), before, "revocation is not reversal or a completion-state downgrade");
}));

test("stale policy epoch and substituted signing key fail closed", () => scenario(s => {
  const fake = crypto.generateKeyPairSync("ed25519");
  const key = path.join(s.directory, "untrusted-public.pem");
  fs.writeFileSync(key, fake.publicKey.export({ type: "spki", format: "pem" }));
  const envelope = { ...s.envelope, signature: s.sign(s.envelope.authorization, fake.privateKey) };
  reject(s.send(envelope, null, key), /untrusted_issuer_key/);
  s.assertEmpty();
  assert.equal(s.admin("from authorized_execution import set_epoch; set_epoch(sys.argv[2],2)").status, 0);
  reject(s.send(), /stale_policy_epoch/);
  s.assertEmpty();
  const renewed = s.envelopeFor(s.request, { policy_epoch: 2 });
  assert.equal(s.send(renewed).status, 0);
  s.assertPair(renewed);
}));

test("same operation with different signed parameters never receives replay success", () => scenario(s => {
  assert.equal(s.send().status, 0);
  const first = s.assertPair();
  const changed = s.envelopeFor({ ...s.request, body: { value: "different signed value" } });
  reject(s.send(changed), /authorization_spent/);
  reject(s.readStatus(s.expected(changed)), /request_history_conflict/);
  assert.equal(s.assertPair(), first);
  assert.equal(JSON.parse(s.readStatus().stdout).record.effect_id, first);
}));

test("eight concurrent processes yield one committed pair and seven rejected replays", () => scenario(async s => {
  const run = () => new Promise((resolve, rejectPromise) => {
    const child = spawn("python3", [provider, s.database, "request", s.issuerFile], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); rejectPromise(Error("atomic race worker timeout")); }, 20_000);
    child.on("error", error => { clearTimeout(timer); rejectPromise(error); });
    child.stdout.on("data", bytes => { stdout += bytes; });
    child.stderr.on("data", bytes => { stderr += bytes; });
    child.on("close", status => { clearTimeout(timer); resolve({ status, stdout, stderr }); });
    child.stdin.end(JSON.stringify(s.envelope));
  });
  const results = await Promise.all(Array.from({ length: 8 }, run));
  assert.equal(results.filter(result => result.status === 0).length, 1, JSON.stringify(results));
  assert.equal(results.filter(result => result.status === 2 && /authorization_spent/.test(result.stderr)).length, 7, JSON.stringify(results));
  const id = s.assertPair();
  assert.equal(JSON.parse(results.find(result => result.status === 0).stdout).effect_id, id);
}));

test("missing provider DB cannot be silently reinitialized by request or read-only status", () => scenario(s => {
  fs.unlinkSync(s.database);
  reject(s.send(), /OperationalError/);
  assert.equal(fs.existsSync(s.database), false);
  reject(s.readStatus(), /OperationalError/);
  assert.equal(fs.existsSync(s.database), false);
}));

test("schema/effect write failure rolls back the claim and does not recreate the schema", () => scenario(s => {
  assert.equal(s.admin("import sqlite3; c=sqlite3.connect(sys.argv[2]); c.execute('DROP TABLE effects'); c.commit()").status, 0);
  reject(s.send(), /OperationalError/);
  const rows = s.admin("import sqlite3; c=sqlite3.connect(sys.argv[2]); assert c.execute('SELECT count(*) FROM claims').fetchone()[0]==0; " +
    "assert c.execute(\"SELECT count(*) FROM sqlite_master WHERE name='effects'\").fetchone()[0]==0");
  assert.equal(rows.status, 0, rows.stderr);
}));

for (const table of ["claims", "effects"]) {
  test(`corrupted ${table} history is rejected, not repaired or treated as replay success`, () => scenario(s => {
    assert.equal(s.send().status, 0);
    const first = s.assertPair();
    assert.equal(s.admin(`import sqlite3; c=sqlite3.connect(sys.argv[2]); c.execute('DELETE FROM ${table}'); c.commit()`).status, 0);
    const before = s.snapshot();
    reject(s.readStatus(), /atomic_history_inconsistent/);
    reject(s.send());
    assert.deepEqual(s.snapshot(), before, "status/rejected request must not invent missing history");
    if (table === "claims") assert.equal(s.snapshot().effects[0][3], first);
  }));
}

test("KNOWN COUNTEREXAMPLE: provider-owned joint rollback revives authorization; retained signed history exposes it", () => scenario(s => {
  const backup = path.join(s.directory, "pre-effect.sqlite");
  fs.copyFileSync(s.database, backup);
  assert.equal(s.send().status, 0);
  const first = s.assertPair();
  const before = s.signedStatus();
  // Deliberately act as provider administrator. This is outside host-only control.
  fs.copyFileSync(backup, s.database);
  assert.equal(s.send().status, 0);
  const second = s.assertPair();
  assert.notEqual(first, second);
  const after = s.signedStatus();
  assert.equal(verifyProviderHistory([before.envelope, after.envelope], {
    challenges: [before.challenge, after.challenge], publicKey: s.statusKeys.publicKey.export({ type: "spki", format: "pem" }),
    operationId: s.request.operation_id, requestSha256: sha(s.envelope.request_bytes), destination: DESTINATION
  }), "CONFLICTING_EVIDENCE");
}));

test("KNOWN COUNTEREXAMPLE: provider administrator can write an ungated row", () => scenario(s => {
  const effect = crypto.randomUUID();
  const result = s.admin("import sqlite3; c=sqlite3.connect(sys.argv[2]); " +
    "c.execute('INSERT INTO effects VALUES (?,?,?,?)',sys.argv[3:7]); c.commit()", s.request.operation_id,
    sha(s.envelope.request_bytes), DESTINATION, effect);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(s.snapshot().effects[0][3], effect);
  assert.equal(s.snapshot().claims.length, 0);
  reject(s.readStatus(), /atomic_history_inconsistent/);
}));

test("explicit initialization preserves spent history and refuses trust-root replacement", () => scenario(s => {
  assert.equal(s.send().status, 0);
  const before = s.snapshot();
  assert.equal(python([provider, s.database, "initialize", s.issuerFile]).status, 0);
  assert.deepEqual(s.snapshot(), before);
  const other = crypto.generateKeyPairSync("ed25519");
  const key = path.join(s.directory, "replacement-public.pem");
  fs.writeFileSync(key, other.publicKey.export({ type: "spki", format: "pem" }));
  reject(python([provider, s.database, "initialize", key]), /trust_configuration_conflict/);
  assert.deepEqual(s.snapshot(), before);
  reject(s.send(), /authorization_spent/);
}));

test("conflicting persisted digest and incorrect status destination cannot rewrite completion", () => scenario(s => {
  assert.equal(s.send().status, 0);
  reject(s.readStatus({ ...s.expected(), destination: "fixture:other" }), /invalid_status_binding/);
  assert.equal(s.admin("import sqlite3; c=sqlite3.connect(sys.argv[2]); " +
    "c.execute('UPDATE claims SET request_sha256=?',('f'*64,)); c.commit()").status, 0);
  const before = s.snapshot();
  reject(s.readStatus(), /atomic_history_inconsistent/);
  reject(s.send(), /authorization_spent/);
  assert.deepEqual(s.snapshot(), before);
}));


test("authorization signer matches Python ASCII-escaped control/integer vectors", () => scenario(s => {
  const vectors = [
    { principal: "principal\x7f" },
    { principal: Array.from({ length: 32 }, (_, code) => String.fromCharCode(code)).join("") },
    { issuer: 'issuer\\with"quotes', policy_id: "policy\b\t\n\f\r" },
    { policy_epoch: Number.MAX_SAFE_INTEGER, expires_at_ms: Number.MAX_SAFE_INTEGER },
    { policy_epoch: 0, expires_at_ms: Number.MIN_SAFE_INTEGER }
  ];
  for (const changes of vectors) {
    const statement = { ...s.envelope.authorization, ...changes };
    const result = s.admin("import json; from authorized_execution import canonical; " +
      "sys.stdout.buffer.write(canonical(json.loads(sys.argv[3])))", JSON.stringify(statement));
    assert.equal(result.status, 0, result.stderr);
    assert.equal(canonicalAuthorization(statement), result.stdout);
  }
  assert.throws(() => canonicalAuthorization({ ...s.envelope.authorization, policy_epoch: Number.MAX_SAFE_INTEGER + 1 }), /safe integers/);
  assert.throws(() => canonicalAuthorization({ ...s.envelope.authorization, expires_at_ms: 1.5 }), /safe integers/);
}));

test("DEL metadata accepts exact authorization profile and rejects generic core encoding", () => scenario(s => {
  const envelope = s.envelopeFor(s.request, { principal: "principal\x7f" });
  const signature = s.signGeneric(envelope.authorization);
  reject(s.send({ ...envelope, signature }), /invalid_authorization_signature/);
  s.assertEmpty();
  assert.equal(s.send(envelope).status, 0);
  s.assertPair(envelope);
}));
