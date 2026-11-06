import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const provider = fileURLToPath(new URL("../pilots/action-boundary/authorized-provider-fixture.py", import.meta.url));
const modules = path.dirname(provider);
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const canonical = obj => JSON.stringify(Object.fromEntries(Object.entries(obj).sort(([a], [b]) => a.localeCompare(b, "en"))));

function scenario(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-auth-exec-"));
  try {
    const db = path.join(directory, "provider.db"), gate = path.join(directory, "gate.db"), keyfile = path.join(directory, "issuer.pem");
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    fs.writeFileSync(keyfile, publicKey.export({ type: "spki", format: "pem" }));
    const admin = (code, ...args) => spawnSync("python3", ["-c", `import sys; sys.path.insert(0,sys.argv[1]); from authorized_execution import ${code}`, modules, ...args], { encoding: "utf8", timeout: 20_000 });
    const init = admin("initialize; initialize(sys.argv[2],sys.argv[3])", gate, keyfile);
    assert.equal(init.status, 0, init.stderr);
    const request = { operation_id: crypto.randomUUID(), destination: "fixture:approved", effect: "payment:simulated", body: { amount: 10000, recipient: "A" } };
    const bytes = JSON.stringify(request);
    const authorization = { version: "aml-authorized-execution/1", issuer: "test-issuer", principal: "test-actor", policy_id: "test-policy", policy_epoch: 1,
      operation_id: request.operation_id, request_sha256: sha(bytes), destination: request.destination, effect: request.effect,
      expires_at_ms: Date.now() + 60_000 };
    const sign = (auth, key = privateKey) => crypto.sign(null, Buffer.concat([Buffer.from("AML-AUTHORIZED-EXECUTION/1\0"), Buffer.from(canonical(auth))]), key).toString("base64");
    const send = (auth = authorization, requestBytes = bytes, signature = sign(auth), publicPath = keyfile) => spawnSync("python3", [provider, db, gate, publicPath],
      { input: JSON.stringify({ authorization: auth, signature, request_bytes: requestBytes }), encoding: "utf8", timeout: 20_000 });
    const count = () => { const r = admin("sqlite3; c=sqlite3.connect(sys.argv[2]); print(c.execute(\"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='effects'\").fetchone()[0] and c.execute('SELECT count(*) FROM effects').fetchone()[0])", db); assert.equal(r.status, 0, r.stderr); return Number(r.stdout); };
    run({ db, gate, keyfile, directory, request, bytes, authorization, privateKey, sign, send, admin, count });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test("signed exact authorization is consumed once at protected provider route", () => scenario(({ send, count }) => {
  assert.equal(send().status, 0);
  const again = send();
  assert.equal(again.status, 2);
  assert.match(again.stderr, /authorization_spent/);
  assert.equal(count(), 1);
}));

test("malicious host cannot forge or mutate protected exact request", () => scenario(({ send, request, bytes, authorization, count }) => {
  const invalid = [
    send({ ...authorization, destination: "fixture:stolen" }),
    send(authorization, JSON.stringify({ ...request, destination: "fixture:stolen" })),
    send(authorization, JSON.stringify({ ...request, body: { amount: 20000, recipient: "A" } })),
    send(authorization, JSON.stringify({ ...request, operation_id: crypto.randomUUID() })),
    send(authorization, bytes, "AAAA")
  ];
  for (const result of invalid) assert.equal(result.status, 2, result.stderr);
  assert.equal(count(), 0);
  assert.equal(send().status, 0);
}));

test("expired, revoked, stale epoch and substituted key reject before effect", () => scenario(({ send, authorization, gate, keyfile, directory, admin, count, sign }) => {
  const expired = { ...authorization, expires_at_ms: Date.now() - 1 };
  assert.match(send(expired, undefined, sign(expired)).stderr, /authorization_expired/);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const other = path.join(directory, "other.pem");
  fs.writeFileSync(other, publicKey.export({ type: "spki", format: "pem" }));
  assert.match(send(authorization, undefined, sign(authorization, privateKey), other).stderr, /untrusted_issuer_key/);
  const revoked = admin("revoke; revoke(sys.argv[2],sys.argv[3])", gate, authorization.operation_id);
  assert.equal(revoked.status, 0, revoked.stderr);
  assert.match(send().stderr, /authorization_revoked/);
  const changed = admin("set_epoch; set_epoch(sys.argv[2],2)", gate);
  assert.equal(changed.status, 0, changed.stderr);
  assert.match(send().stderr, /stale_policy_epoch/);
  assert.equal(count(), 0);
  assert.ok(fs.existsSync(keyfile));
}));

test("separate processes racing to consume one signed authorization yield one effect", () => scenario(({ db, gate, keyfile, authorization, bytes, sign, count }) => {
  const input = JSON.stringify({ authorization, signature: sign(authorization), request_bytes: bytes });
  const inputFile = path.join(path.dirname(db), "input.json");
  fs.writeFileSync(inputFile, input);
  const result = spawnSync("bash", ["-c", "for n in $(seq 1 8); do python3 \"$1\" \"$2\" \"$3\" \"$4\" < \"$5\" > /dev/null 2>&1 & done; wait", "_", provider, db, gate, keyfile, inputFile],
    { encoding: "utf8", timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(count(), 1);
}));

test("missing retained authority fails closed; provider history deletion does not revive signed grant", () => scenario(({ db, gate, send, count, admin }) => {
  assert.equal(send().status, 0);
  const removed = admin("sqlite3; c=sqlite3.connect(sys.argv[2]); c.execute('DELETE FROM effects'); c.commit()", db);
  assert.equal(removed.status, 0, removed.stderr);
  assert.match(send().stderr, /authorization_spent/);
  assert.equal(count(), 0);
  fs.unlinkSync(gate);
  assert.equal(send().status, 2);
  assert.equal(count(), 0);
}));

test("malformed and duplicate-key request cannot consume a valid grant", () => scenario(({ send, authorization, bytes, count, sign }) => {
  const withDuplicate = bytes.replace('"destination":"fixture:approved"', '"destination":"fixture:approved","destination":"fixture:stolen"');
  const duplicateAuth = { ...authorization, request_sha256: sha(withDuplicate) };
  assert.match(send(duplicateAuth, withDuplicate, sign(duplicateAuth)).stderr, /duplicate_request_key/);
  assert.match(send(authorization, "[]").stderr, /request_digest_mismatch/);
  assert.equal(count(), 0);
  assert.equal(send().status, 0);
}));
