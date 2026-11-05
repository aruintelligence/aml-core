import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createFileRevocationHandoff } from "../pilots/action-boundary/file-revocation-handoff.mjs";
import { createSqliteEpochCoordinator } from "../pilots/action-boundary/sqlite-epoch-coordinator.mjs";

const provider = fileURLToPath(new URL("../pilots/action-boundary/sqlite-provider-fixture.py", import.meta.url));

async function scenario(fault) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aml-coordinator-provider-"));
  const authorityDirectory = path.join(root, "authority");
  const coordinatorDirectory = path.join(root, "coordinator");
  const providerDirectory = path.join(root, "provider");
  fs.mkdirSync(coordinatorDirectory, { mode: 0o700 });
  fs.mkdirSync(providerDirectory, { mode: 0o700 });
  const coordinator = createSqliteEpochCoordinator({
    database: path.join(coordinatorDirectory, "authority.sqlite") });
  const providerDatabase = path.join(providerDirectory, "effects.sqlite");
  const callProvider = (command, input) => spawnSync("python3", [provider, providerDatabase, command],
    { input, encoding: "utf8", timeout: 20_000 });
  try {
    coordinator.initialize();
    const operationId = crypto.randomUUID();
    const input = { tenant: "tenant-a", issuer: "host-a", actor: "fixture-reviewer",
      audience: "fixture-provider", tool: "write_record", policy: { revision: 1 },
      preparedRequest: { destination: "fixture:outbox", body: "approved" } };
    const host = createFileRevocationHandoff({ directory: authorityDirectory, epochAnchor: coordinator });
    const grant = host.issue(input, { operationId });
    let callbacks = 0;
    // The provider request is derived from the host's frozen prepared request,
    // and retains the same operation ID across reconciliation.
    const first = await host.dispatch({ ...input, grant_id: grant.grant_id,
      execute: frozen => {
        callbacks++;
        const requestBytes = JSON.stringify({ operation_id: operationId, ...frozen });
        const requestSha256 = crypto.createHash("sha256").update(requestBytes).digest("hex");
        const child = callProvider("request", JSON.stringify({ request_bytes: requestBytes,
          request_sha256: requestSha256, fault }));
        assert.equal(child.status, fault === "after_commit" ? 75 : 76, child.stderr);
        throw new Error("provider_acknowledgment_lost");
      } });
    assert.equal(first.status, "outcome_unknown");
    assert.equal(first.dispatch_count, 1);
    assert.equal(coordinator.inspect().claims, 1);
    const restarted = createFileRevocationHandoff({ directory: authorityDirectory,
      epochAnchor: createSqliteEpochCoordinator({ database: path.join(coordinatorDirectory,
        "authority.sqlite") }) });
    const replay = await restarted.dispatch({ ...input, grant_id: grant.grant_id,
      execute: () => { callbacks++; } });
    assert.equal(replay.dispatch_count, 0);
    assert.equal(callbacks, 1);
    const read = callProvider("status", operationId);
    assert.equal(read.status, 0, read.stderr);
    const providerRecord = JSON.parse(read.stdout).record;
    if (fault === "after_commit") {
      assert.equal(providerRecord.operation_id, operationId);
      assert.equal(providerRecord.destination, input.preparedRequest.destination);
      assert.ok(providerRecord.effect_id);
    } else {
      assert.equal(providerRecord, null);
    }
    return { host: first.status, replay: replay.status, provider_record: Boolean(providerRecord),
      effect_id: providerRecord?.effect_id ?? null, callbacks, coordinator_claims: 1 };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test("post-commit lost acknowledgment reconciles without grant replay", async () => {
  const result = await scenario("after_commit");
  assert.equal(result.host, "outcome_unknown");
  assert.equal(result.provider_record, true);
  assert.equal(result.callbacks, 1);
});

test("pre-commit loss remains uncertain without a provider record", async () => {
  const result = await scenario("before_commit");
  assert.equal(result.host, "outcome_unknown");
  assert.equal(result.provider_record, false);
  assert.equal(result.callbacks, 1);
});
