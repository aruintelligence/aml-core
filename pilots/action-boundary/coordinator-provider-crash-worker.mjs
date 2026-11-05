#!/usr/bin/env node
// Controlled crash fixture. A real process exit inside execute strands the
// authority lock; restart reports the provider record but does not retry.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createFileRevocationHandoff } from "./file-revocation-handoff.mjs";
import { createSqliteEpochCoordinator } from "./sqlite-epoch-coordinator.mjs";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const [mode, directory, fault] = process.argv.slice(2);
if (!["start", "recover"].includes(mode) || !path.isAbsolute(directory) ||
    (mode === "start" && !["before_commit", "after_commit"].includes(fault))) {
  throw Error("invalid_crash_fixture_invocation");
}
const provider = fileURLToPath(new URL("./sqlite-provider-fixture.py", import.meta.url));
const signer = fileURLToPath(new URL("./signed-provider-status.mjs", import.meta.url));
const verifier = fileURLToPath(new URL("./verify-provider-status.mjs", import.meta.url));
const journal = path.join(directory, "host-intent.json");
const coordinatorDb = path.join(directory, "coordinator", "authority.sqlite");
const providerDb = path.join(directory, "provider", "effects.sqlite");
const coordinator = createSqliteEpochCoordinator({ database: coordinatorDb });
const host = createFileRevocationHandoff({ directory: path.join(directory, "authority"),
  epochAnchor: coordinator });
const callProvider = (command, input) => spawnSync("python3", [provider, providerDb, command],
  { input, encoding: "utf8", timeout: 20_000 });
const hash = value => crypto.createHash("sha256").update(value).digest("hex");

function persist(record) {
  const fd = fs.openSync(journal, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(record) + "\n"); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  const parent = fs.openSync(directory, "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}

if (mode === "start") {
  fs.mkdirSync(path.dirname(coordinatorDb), { mode: 0o700 });
  fs.mkdirSync(path.dirname(providerDb), { mode: 0o700 });
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(path.join(directory, "provider", "private.pem"),
    privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(path.join(directory, "pinned-provider-public.pem"),
    publicKey.export({ type: "spki", format: "pem" }));
  coordinator.initialize();
  const operationId = crypto.randomUUID();
  const input = { tenant: "tenant-a", issuer: "host-a", actor: "fixture-reviewer",
    audience: "fixture-provider", tool: "write_record", policy: { revision: 1 },
    preparedRequest: { destination: "fixture:outbox", body: "approved" } };
  const grant = host.issue(input, { operationId });
  // Intent is synced before dispatch. This is an integrity-checked local
  // record, not an authenticated or independently retained journal.
  const requestBytes = JSON.stringify({ operation_id: operationId,
    ...JSON.parse(canonicalJSONStringify(input.preparedRequest)) });
  persist({ protocol: "aml-coordinator-provider-crash-test/1", operationId,
    input, grantId: grant.grant_id, requestBytes, requestSha256: hash(requestBytes) });
  const decision = await host.dispatch({ ...input, grant_id: grant.grant_id, execute: frozen => {
    assert.equal(JSON.stringify({ operation_id: operationId, ...frozen }), requestBytes);
    const child = callProvider("request", JSON.stringify({ request_bytes: requestBytes,
      request_sha256: hash(requestBytes), fault }));
    assert.equal(child.status, fault === "after_commit" ? 75 : 76, child.stderr);
    process.exit(77); // Bypass dispatch's finally and outcome persistence.
  } });
  throw Error(`host_crash_not_reached:${JSON.stringify(decision)}`);
} else {
  const record = JSON.parse(fs.readFileSync(journal, "utf8"));
  if (record.protocol !== "aml-coordinator-provider-crash-test/1" ||
      hash(record.requestBytes) !== record.requestSha256 ||
      JSON.parse(record.requestBytes).operation_id !== record.operationId ||
      JSON.parse(record.requestBytes).destination !== record.input.preparedRequest.destination ||
      JSON.parse(record.requestBytes).body !== record.input.preparedRequest.body) {
    throw Error("invalid_host_intent");
  }
  let callbacks = 0;
  const replay = await host.dispatch({ ...record.input, grant_id: record.grantId,
    execute: () => { callbacks++; } });
  const result = callProvider("status", record.operationId);
  if (result.error || result.status !== 0) throw result.error || Error(result.stderr);
  const providerRecord = JSON.parse(result.stdout).record;
  const matches = providerRecord !== null &&
    providerRecord.operation_id === record.operationId &&
    providerRecord.request_sha256 === record.requestSha256 &&
    providerRecord.destination === record.input.preparedRequest.destination;
  const signed = spawnSync(process.execPath, [signer, providerDb,
    path.join(directory, "provider", "private.pem")],
  { input: record.operationId, encoding: "utf8", timeout: 20_000 });
  if (signed.error || signed.status !== 0) throw signed.error || Error("provider_signing_failed");
  const verified = spawnSync(process.execPath, [verifier,
    path.join(directory, "pinned-provider-public.pem"), record.operationId,
    record.requestSha256, record.input.preparedRequest.destination],
  { input: signed.stdout.trim(), encoding: "utf8", timeout: 20_000 });
  if (verified.error || verified.status !== 0) throw verified.error || Error("provider_verification_failed");
  const verification = JSON.parse(verified.stdout).result;
  console.log(JSON.stringify({ protocol: "aml-coordinator-provider-crash-report/1",
    replay_status: replay.status, replay_reason: replay.reason, callbacks,
    coordinator_claims: coordinator.inspect().claims,
    provider_record_matches: matches, provider_record_absent: providerRecord === null,
    provider_signature_result: verification, host_outcome: "unknown",
    independent_confirmation: false, retry_attempted: false }));
}
