import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createFileAuthorityAnchor, createFileRevocationHandoff } from
  "../pilots/action-boundary/file-revocation-handoff.mjs";

const verifier = fileURLToPath(new URL(
  "../pilots/action-boundary/verify_authority_checkpoint.py", import.meta.url));
const input = () => ({ tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a",
  audience: "mail-service", tool: "send_message", policy: { revision: 1 },
  preparedRequest: { to: "team@example.test", body: "Approved" } });

function verify(directory, anchorDirectory) {
  const result = spawnSync("python3", [verifier, directory, anchorDirectory],
    { encoding: "utf8" });
  assert.equal(result.error, undefined);
  return { code: result.status, output: JSON.parse(result.stdout), stderr: result.stderr };
}

function rehashJointSnapshot(directory, anchorDirectory) {
  const sha256 = value => createHash("sha256").update(value).digest("hex");
  const entries = [];
  for (const kind of ["epochs", "grants", "operations", "claimed"]) {
    for (const name of fs.readdirSync(path.join(directory, kind)).sort()) {
      const record = JSON.parse(fs.readFileSync(path.join(directory, kind, name), "utf8"));
      entries.push([`${kind}/${name}`, sha256(canonicalJSONStringify(record))]);
    }
  }
  const mode = JSON.parse(fs.readFileSync(path.join(directory, "authority-mode.json"), "utf8"));
  entries.push(["authority-mode.json", sha256(canonicalJSONStringify(mode))]);
  const state_sha256 = sha256(JSON.stringify(entries));
  for (const root of [directory, anchorDirectory]) {
    const file = path.join(root, "checkpoint.json");
    const checkpoint = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, JSON.stringify({ ...checkpoint, state_sha256 }) + "\n");
  }
}

async function fixture(run) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-checkpoint-verifier-"));
  const directory = path.join(parent, "authority");
  const anchorDirectory = path.join(parent, "outside-anchor");
  try {
    const anchor = createFileAuthorityAnchor({ directory: anchorDirectory });
    const host = createFileRevocationHandoff({ directory, anchor });
    await run({ parent, directory, anchorDirectory, anchor, host });
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
}

test("Python verifier recomputes genesis, issue, claim and revoke without writing", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    const genesis = verify(directory, anchorDirectory);
    assert.deepEqual([genesis.code, genesis.output.status, genesis.output.sequence],
      [0, "consistent", 0]);
    const grant = host.issue(input(), { operationId: "checkpoint-verifier-intent" });
    assert.equal(verify(directory, anchorDirectory).output.records.operations, 1);
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => "local-effect" })).status, "returned");
    host.revokeIssuer(input());
    const local = fs.readFileSync(path.join(directory, "checkpoint.json"));
    const external = fs.readFileSync(path.join(anchorDirectory, "checkpoint.json"));
    const verified = verify(directory, anchorDirectory);
    assert.deepEqual([verified.code, verified.output.status, verified.output.sequence,
      verified.output.records], [0, "consistent", 3,
      { epochs: 1, grants: 1, operations: 1, claimed: 1 }]);
    assert.deepEqual(fs.readFileSync(path.join(directory, "checkpoint.json")), local);
    assert.deepEqual(fs.readFileSync(path.join(anchorDirectory, "checkpoint.json")), external);
    assert.equal(fs.existsSync(path.join(directory, "authority.lock")), false);
  }));

test("verifier rejects a jointly lowered checkpoint sequence despite matching state", () =>
  fixture(async ({ directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input());
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => "local-effect" })).status, "returned");
    host.revokeIssuer(input());
    host.revokeIssuer(input());
    const checkpoint = anchor.read();
    assert.equal(checkpoint.sequence, 4);
    for (const root of [directory, anchorDirectory]) {
      fs.writeFileSync(path.join(root, "checkpoint.json"),
        JSON.stringify({ ...checkpoint, sequence: 3 }) + "\n");
    }
    const result = verify(directory, anchorDirectory);
    assert.deepEqual([result.code, result.output.status, result.output.reason],
      [1, "inconsistent", "checkpoint_sequence_shortfall"]);
  }));

test("verifier reconstructs first issue and revoke heads from current records", async () => {
  for (const transition of ["issue", "revoke"]) {
    await fixture(async ({ directory, anchorDirectory, anchor, host }) => {
      if (transition === "issue") host.issue(input(), { operationId: "first-intent" });
      else host.revokeIssuer(input());
      const checkpoint = anchor.read();
      assert.equal(checkpoint.sequence, 1);
      assert.equal(verify(directory, anchorDirectory).output.status, "consistent", transition);
      const wrongHead = checkpoint.head_sha256 === "f".repeat(64) ?
        "e".repeat(64) : "f".repeat(64);
      for (const root of [directory, anchorDirectory]) {
        fs.writeFileSync(path.join(root, "checkpoint.json"),
          JSON.stringify({ ...checkpoint, head_sha256: wrongHead }) + "\n");
      }
      const result = verify(directory, anchorDirectory);
      assert.deepEqual([result.code, result.output.status, result.output.reason],
        [1, "inconsistent", "checkpoint_head_mismatch"], transition);
    });
  }
});

test("verifier rejects a jointly rehashed operation with no grant backlink", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    const grant = host.issue(input());
    const saved = JSON.parse(fs.readFileSync(path.join(directory, "grants",
      `${grant.grant_id}.json`), "utf8"));
    const operationHash = "a".repeat(64);
    fs.writeFileSync(path.join(directory, "operations", `${operationHash}.json`),
      JSON.stringify({ protocol: "aml-file-authority-operation/1",
        operation_sha256: operationHash, grant_id: grant.grant_id,
        issuer_sha256: saved.issuer_sha256, binding_sha256: saved.binding_sha256,
        epoch: saved.epoch }) + "\n", { mode: 0o600 });
    rehashJointSnapshot(directory, anchorDirectory);
    const result = verify(directory, anchorDirectory);
    assert.deepEqual([result.code, result.output.status, result.output.reason],
      [1, "inconsistent", "operation_grant_mismatch"]);
  }));

test("verifier rejects a jointly rehashed grant exceeding the issuance TTL", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    const grant = host.issue(input(), { ttlMs: 300_000 });
    assert.equal(verify(directory, anchorDirectory).output.status, "consistent");
    const file = path.join(directory, "grants", `${grant.grant_id}.json`);
    const saved = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, JSON.stringify({ ...saved,
      expires_at_ms: saved.issued_at_ms + 300_001 }) + "\n");
    rehashJointSnapshot(directory, anchorDirectory);
    const result = verify(directory, anchorDirectory);
    assert.deepEqual([result.code, result.output.status, result.output.reason],
      [1, "inconsistent", "invalid_grant_record"]);
  }));

test("verifier rejects a jointly rehashed grant ahead of its issuer epoch", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    const grant = host.issue(input());
    const file = path.join(directory, "grants", `${grant.grant_id}.json`);
    const saved = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, JSON.stringify({ ...saved, epoch: saved.epoch + 1 }) + "\n");
    rehashJointSnapshot(directory, anchorDirectory);
    const result = verify(directory, anchorDirectory);
    assert.deepEqual([result.code, result.output.status, result.output.reason],
      [1, "inconsistent", "grant_epoch_ahead"]);
  }));

test("verifier rejects a jointly rehashed grant issued after the persisted clock", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    const grant = host.issue(input());
    const file = path.join(directory, "grants", `${grant.grant_id}.json`);
    const saved = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, JSON.stringify({ ...saved,
      issued_at_ms: saved.issued_at_ms + 1,
      expires_at_ms: saved.expires_at_ms + 1 }) + "\n");
    rehashJointSnapshot(directory, anchorDirectory);
    const result = verify(directory, anchorDirectory);
    assert.deepEqual([result.code, result.output.status, result.output.reason],
      [1, "inconsistent", "grant_issued_after_clock"]);
  }));

test("verifier rejects a missing clock after grant issuance", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    host.issue(input());
    fs.rmSync(path.join(directory, "clock.json"));
    const result = verify(directory, anchorDirectory);
    assert.deepEqual([result.code, result.output.status, result.output.reason],
      [1, "inconsistent", "authority_clock_missing"]);
  }));

test("verifier rejects a restored local checkpoint and selective decision changes", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    const old = fs.readFileSync(path.join(directory, "checkpoint.json"));
    const modeFile = path.join(directory, "authority-mode.json");
    const savedMode = fs.readFileSync(modeFile);
    fs.writeFileSync(modeFile, JSON.stringify({ protocol: "aml-file-authority-mode/1",
      mode: "checkpoint-claim-anchored" }) + "\n");
    assert.equal(verify(directory, anchorDirectory).output.reason, "state_mismatch");
    fs.writeFileSync(modeFile, savedMode);
    const grant = host.issue(input());
    const localFile = path.join(directory, "checkpoint.json");
    fs.writeFileSync(localFile, old);
    assert.deepEqual([verify(directory, anchorDirectory).code,
      verify(directory, anchorDirectory).output.reason], [1, "anchor_mismatch"]);
    fs.copyFileSync(path.join(anchorDirectory, "checkpoint.json"), localFile);
    const grantFile = path.join(directory, "grants", `${grant.grant_id}.json`);
    const savedGrant = fs.readFileSync(grantFile);
    fs.rmSync(grantFile);
    assert.equal(verify(directory, anchorDirectory).output.reason, "state_mismatch");
    fs.writeFileSync(grantFile, savedGrant, { mode: 0o600 });
    fs.writeFileSync(modeFile, JSON.stringify({ protocol: "aml-file-authority-mode/1",
      mode: "checkpoint-claim-anchored" }) + "\n");
    assert.equal(verify(directory, anchorDirectory).output.reason, "grant_mode_mismatch");
    fs.writeFileSync(modeFile, savedMode);
    assert.equal(verify(directory, anchorDirectory).output.status, "consistent");
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => "local-effect" })).status, "returned");
    fs.rmSync(path.join(directory, "claimed", `${grant.grant_id}.json`));
    assert.equal(verify(directory, anchorDirectory).output.reason, "state_mismatch");
  }));

test("verifier fails closed on duplicate keys, symlinks, unexpected entries and legacy protocol", () =>
  fixture(async ({ directory, anchorDirectory, host }) => {
    const checkpointFile = path.join(directory, "checkpoint.json");
    const original = fs.readFileSync(checkpointFile);
    fs.writeFileSync(checkpointFile, '{"protocol":"aml-file-authority-checkpoint/3",'
      + '"protocol":"aml-file-authority-checkpoint/3"}\n');
    assert.equal(verify(directory, anchorDirectory).output.reason, "duplicate_json_key");
    fs.rmSync(checkpointFile);
    fs.symlinkSync(path.join(anchorDirectory, "checkpoint.json"), checkpointFile);
    assert.deepEqual([verify(directory, anchorDirectory).code,
      verify(directory, anchorDirectory).output.reason], [1, "unreadable_or_invalid_input"]);
    fs.rmSync(checkpointFile);
    fs.writeFileSync(checkpointFile, original, { mode: 0o600 });
    const extra = path.join(directory, "claimed", "uncommitted.tmp");
    fs.writeFileSync(extra, "{}");
    assert.equal(verify(directory, anchorDirectory).output.reason, "unexpected_state_entry");
    fs.rmSync(extra);
    const grant = host.issue(input());
    const grantFile = path.join(directory, "grants", `${grant.grant_id}.json`);
    const saved = fs.readFileSync(grantFile);
    fs.writeFileSync(grantFile, JSON.stringify({ ...JSON.parse(saved), extra: {} }) + "\n");
    assert.equal(verify(directory, anchorDirectory).output.reason, "invalid_record_fields");
    fs.writeFileSync(grantFile, saved);
    const legacy = JSON.parse(original);
    legacy.protocol = "aml-file-authority-checkpoint/2";
    fs.writeFileSync(checkpointFile, JSON.stringify(legacy) + "\n");
    assert.equal(verify(directory, anchorDirectory).output.reason,
      "unsupported_checkpoint_protocol");
  }));

test("verifier rejects an active or stranded authority lock", () =>
  fixture(async ({ parent, directory, anchorDirectory }) => {
    const lock = path.join(directory, "authority.lock");
    fs.mkdirSync(lock, { mode: 0o700 });
    assert.deepEqual([verify(directory, anchorDirectory).code,
      verify(directory, anchorDirectory).output.reason], [1, "authority_busy_or_crashed"]);
    fs.rmdirSync(lock);
    fs.symlinkSync(path.join(parent, "missing-lock-target"), lock);
    assert.equal(verify(directory, anchorDirectory).output.reason, "authority_busy_or_crashed");
  }));

test("two jointly restored copies can pass, while one old copy fails", () =>
  fixture(async ({ parent, directory, anchorDirectory, host }) => {
    const oldAuthority = path.join(parent, "old-authority");
    const oldAnchor = path.join(parent, "old-anchor");
    fs.cpSync(directory, oldAuthority, { recursive: true });
    fs.cpSync(anchorDirectory, oldAnchor, { recursive: true });
    for (const child of [oldAuthority, oldAnchor,
      ...["epochs", "grants", "operations", "claimed", "outcomes"]
        .map(name => path.join(oldAuthority, name))]) fs.chmodSync(child, 0o700);
    for (const file of [path.join(oldAuthority, "checkpoint.json"),
      path.join(oldAuthority, "authority-mode.json"),
      path.join(oldAnchor, "checkpoint.json")]) fs.chmodSync(file, 0o600);
    host.issue(input());
    assert.equal(verify(oldAuthority, anchorDirectory).output.reason, "anchor_mismatch");
    const jointlyRestored = verify(oldAuthority, oldAnchor);
    assert.deepEqual([jointlyRestored.code, jointlyRestored.output.sequence], [0, 0]);
  }));
