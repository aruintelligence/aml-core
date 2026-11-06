import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const root = fileURLToPath(new URL("../pilots/action-boundary/", import.meta.url));
const provider = path.join(root, "sqlite-provider-fixture.py");
const signer = path.join(root, "signed-provider-status.mjs");
const verifier = path.join(root, "verify-provider-status.mjs");
const historyVerifier = path.join(root, "verify-provider-history.mjs");
const witness = path.join(root, "sqlite-status-witness.py");

function fixture(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-signed-provider-"));
  try {
    const database = path.join(directory, "effects.sqlite");
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const privateFile = path.join(directory, "provider-private.pem");
    const publicFile = path.join(directory, "pinned-public.pem");
    fs.writeFileSync(privateFile, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    fs.writeFileSync(publicFile, publicKey.export({ type: "spki", format: "pem" }));
    const operationId = crypto.randomUUID();
    const requestBytes = JSON.stringify({ operation_id: operationId,
      destination: "fixture:outbox", body: "approved" });
    const requestSha256 = crypto.createHash("sha256").update(requestBytes).digest("hex");
    const request = spawnSync("python3", [provider, database, "request"],
      { encoding: "utf8", input: JSON.stringify({ request_bytes: requestBytes,
        request_sha256: requestSha256 }), timeout: 20_000 });
    assert.equal(request.status, 0, request.stderr);
    const sign = (op, challenge) => {
      const result = spawnSync(process.execPath, [signer, database, privateFile,
        ...(challenge === undefined ? [] : [challenge])],
        { encoding: "utf8", input: op, timeout: 20_000 });
      assert.equal(result.status, 0, result.stderr);
      return JSON.parse(result.stdout);
    };
    const verify = (envelope, { key = publicFile, op = operationId,
      sha = requestSha256, destination = "fixture:outbox", challenge } = {}) => {
      const result = spawnSync(process.execPath, [verifier, key, op, sha, destination,
        ...(challenge === undefined ? [] : [challenge])],
        { encoding: "utf8", input: typeof envelope === "string" ? envelope :
          canonicalJSONStringify(envelope), timeout: 20_000 });
      return { ...JSON.parse(result.stdout), exit: result.status };
    };
    const verifyHistory = (envelopes, challenges) => {
      const result = spawnSync(process.execPath, [historyVerifier, publicFile,
        operationId, requestSha256, "fixture:outbox"], { encoding: "utf8",
        input: canonicalJSONStringify({ envelopes, challenges }), timeout: 20_000 });
      return JSON.parse(result.stdout).result;
    };
    run({ sign, verify, verifyHistory, operationId, requestSha256, publicFile, directory, database });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test("pinned provider signature reports a committed fixture effect, not independent confirmation", () =>
  fixture(({ sign, verify, operationId }) => {
    const evidence = sign(operationId);
    assert.equal(verify(evidence).result, "PROVIDER_REPORTED");
    assert.equal(verify(evidence).independent_confirmation, false);
    assert.equal(verify(evidence).exit, 0);
  }));

test("forged completion, operation substitution, request mutation and key substitution are rejected", () =>
  fixture(({ sign, verify, operationId, directory }) => {
    const evidence = sign(operationId);
    const forged = structuredClone(evidence);
    forged.record.effect_id = crypto.randomUUID();
    assert.equal(verify(forged).result, "REJECTED");
    assert.equal(verify(evidence, { op: crypto.randomUUID() }).result, "REJECTED");
    assert.equal(verify(evidence, { sha: "f".repeat(64) }).result, "REJECTED");
    assert.equal(verify(evidence, { destination: "fixture:other" }).result, "REJECTED");
    const { publicKey } = crypto.generateKeyPairSync("ed25519");
    const substituted = path.join(directory, "other-public.pem");
    fs.writeFileSync(substituted, publicKey.export({ type: "spki", format: "pem" }));
    assert.equal(verify(evidence, { key: substituted }).result, "REJECTED");
    const raw = canonicalJSONStringify(evidence);
    assert.equal(verify(raw.replace('"issuer":"fixture-provider",',
      '"issuer":"attacker","issuer":"fixture-provider",')).result, "REJECTED");
    assert.equal(verify(` ${raw}`).result, "REJECTED");
  }));

test("signed absence is incomplete; invented provider completion is unsupported", () =>
  fixture(({ sign, verify }) => {
    const absent = crypto.randomUUID();
    const evidence = sign(absent);
    assert.equal(evidence.record, null);
    assert.equal(verify(evidence, { op: absent }).result, "INCOMPLETE");
    assert.equal(verify({ ...evidence, record: { effect_id: crypto.randomUUID() } },
      { op: absent }).result, "REJECTED");
  }));

test("substituting both the trust root and signed record defeats unpinned verification", () =>
  fixture(({ sign, verify, operationId, directory }) => {
    const evidence = sign(operationId);
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const fake = structuredClone(evidence);
    fake.record.effect_id = crypto.randomUUID();
    const statement = { protocol: fake.protocol, issuer: fake.issuer,
      operation_id: fake.operation_id, record: fake.record };
    fake.signature = crypto.sign(null, Buffer.concat([
      Buffer.from("AML-LOCAL-PROVIDER-STATUS/1\0"),
      Buffer.from(canonicalJSONStringify(statement))
    ]), privateKey).toString("base64");
    const attackerRoot = path.join(directory, "attacker-root.pem");
    fs.writeFileSync(attackerRoot, publicKey.export({ type: "spki", format: "pem" }));
    assert.equal(verify(fake).result, "REJECTED", "pinned genuine root rejects fabrication");
    assert.equal(verify(fake, { key: attackerRoot }).result, "PROVIDER_REPORTED",
      "caller-supplied attacker root can authenticate a forged record");
  }));

test("version 2 status rejects replay under a fresh verifier challenge", () =>
  fixture(({ sign, verify, operationId }) => {
    const firstChallenge = crypto.randomBytes(32).toString("hex");
    const nextChallenge = crypto.randomBytes(32).toString("hex");
    const first = sign(operationId, firstChallenge);
    assert.equal(verify(first, { challenge: firstChallenge }).result, "PROVIDER_REPORTED");
    assert.equal(verify(first, { challenge: nextChallenge }).result, "REJECTED");
    assert.equal(verify(first).result, "REJECTED", "version 1 cannot accept version 2 bytes");
    const next = sign(operationId, nextChallenge);
    assert.equal(verify(next, { challenge: nextChallenge }).result, "PROVIDER_REPORTED");
    assert.equal(verify(next, { challenge: firstChallenge }).result, "REJECTED");
  }));

test("two valid signatures expose a deleted provider row as conflicting evidence", () =>
  fixture(({ sign, verifyHistory, operationId, database }) => {
    const a = crypto.randomBytes(32).toString("hex");
    const b = crypto.randomBytes(32).toString("hex");
    const before = sign(operationId, a);
    const deleteRow = spawnSync("python3", ["-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DELETE FROM effects'); c.commit()",
      database], { encoding: "utf8", timeout: 20_000 });
    assert.equal(deleteRow.status, 0, deleteRow.stderr);
    const after = sign(operationId, b);
    assert.equal(after.record, null);
    assert.equal(verifyHistory([before, after], [a, b]), "CONFLICTING_EVIDENCE");
    assert.equal(verifyHistory([after], [b]), "INCOMPLETE",
      "without retained earlier evidence, rollback cannot be detected");
    assert.equal(verifyHistory([before, before], [a, b]), "REJECTED",
      "a response cannot be reused as evidence of a second challenge");
  }));

test("separate retained witness exposes provider rollback across processes", () =>
  fixture(({ sign, verifyHistory, operationId, database, directory, publicFile }) => {
    const witnessDirectory = path.join(directory, "retained-witness");
    fs.mkdirSync(witnessDirectory, { mode: 0o700 });
    const witnessDb = path.join(witnessDirectory, "status.sqlite");
    const call = (action, input) => spawnSync("python3", [witness, witnessDb, action,
      ...(action === "read" ? [] : [publicFile])],
      { input, encoding: "utf8", timeout: 20_000 });
    assert.equal(call("initialize", "").status, 0);
    const firstChallenge = crypto.randomBytes(32).toString("hex");
    const first = sign(operationId, firstChallenge);
    assert.equal(call("append", canonicalJSONStringify(first)).status, 0);
    const duplicate = call("append", canonicalJSONStringify(first));
    assert.equal(JSON.parse(duplicate.stdout).duplicate, true);
    const removed = spawnSync("python3", ["-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DELETE FROM effects'); c.commit()",
      database], { encoding: "utf8", timeout: 20_000 });
    assert.equal(removed.status, 0, removed.stderr);
    const secondChallenge = crypto.randomBytes(32).toString("hex");
    const second = sign(operationId, secondChallenge);
    assert.equal(call("append", canonicalJSONStringify(second)).status, 0);
    const read = call("read", operationId);
    assert.equal(read.status, 0, read.stderr);
    const retained = JSON.parse(read.stdout).envelopes;
    assert.equal(retained.length, 2);
    assert.equal(verifyHistory(retained, [firstChallenge, secondChallenge]), "CONFLICTING_EVIDENCE");
    const wrong = structuredClone(first);
    wrong.record.effect_id = crypto.randomUUID();
    assert.notEqual(call("append", canonicalJSONStringify(wrong)).status, 0,
      "witness challenge slot cannot be replaced with a different record");
    assert.equal(verifyHistory(JSON.parse(call("read", operationId).stdout).envelopes,
      [firstChallenge, secondChallenge]), "CONFLICTING_EVIDENCE");
  }));

test("ambiguous JSON cannot occupy a valid witness challenge slot", () =>
  fixture(({ sign, operationId, directory, publicFile }) => {
    const database = path.join(directory, "witness.sqlite");
    const challenge = crypto.randomBytes(32).toString("hex");
    const signed = canonicalJSONStringify(sign(operationId, challenge));
    const ambiguous = signed.replace('"issuer":"fixture-provider",',
      '"issuer":"attacker","issuer":"fixture-provider",');
    const append = input => spawnSync("python3", [witness, database, "append", publicFile],
      { input, encoding: "utf8", timeout: 20_000 });
    assert.equal(spawnSync("python3", [witness, database, "initialize", publicFile]).status, 0);
    assert.notEqual(append(ambiguous).status, 0);
    const valid = append(signed);
    assert.equal(valid.status, 0, valid.stderr);
    assert.equal(JSON.parse(valid.stdout).duplicate, false);
  }));

test("forged signature cannot occupy a pinned witness slot", () =>
  fixture(({ sign, operationId, directory, publicFile }) => {
    const database = path.join(directory, "witness.sqlite");
    const challenge = crypto.randomBytes(32).toString("hex");
    const legitimate = sign(operationId, challenge);
    const forged = { ...legitimate, signature: "A".repeat(86) + "==" };
    const append = value => spawnSync("python3", [witness, database, "append", publicFile],
      { input: canonicalJSONStringify(value), encoding: "utf8", timeout: 20_000 });
    assert.equal(spawnSync("python3", [witness, database, "initialize", publicFile]).status, 0);
    const rejected = append(forged);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /invalid_witness_signature/);
    const accepted = append(legitimate);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).duplicate, false);
  }));

test("initialized witness rejects a caller-supplied replacement trust root", () =>
  fixture(({ sign, operationId, directory, publicFile }) => {
    const database = path.join(directory, "witness-root.sqlite");
    const challenge = crypto.randomBytes(32).toString("hex");
    const legitimate = sign(operationId, challenge);
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const attackerKey = path.join(directory, "attacker-public.pem");
    fs.writeFileSync(attackerKey, publicKey.export({ type: "spki", format: "pem" }));
    const fake = structuredClone(legitimate);
    fake.record.effect_id = crypto.randomUUID();
    const { signature, ...statement } = fake;
    fake.signature = crypto.sign(null, Buffer.concat([
      Buffer.from("AML-LOCAL-PROVIDER-STATUS/2\0"),
      Buffer.from(canonicalJSONStringify(statement))
    ]), privateKey).toString("base64");
    const invoke = (action, key, value = "") => spawnSync("python3",
      [witness, database, action, key], { input: value, encoding: "utf8", timeout: 20_000 });
    assert.equal(invoke("initialize", publicFile).status, 0);
    const rejected = invoke("append", attackerKey, canonicalJSONStringify(fake));
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /witness_trust_root_mismatch/);
    const accepted = invoke("append", publicFile, canonicalJSONStringify(legitimate));
    assert.equal(accepted.status, 0, accepted.stderr);
  }));
