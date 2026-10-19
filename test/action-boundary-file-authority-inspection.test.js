import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createFileAuthorityAnchor, createFileRevocationHandoff,
  inspectFileRevocationHandoff } from "../pilots/action-boundary/file-revocation-handoff.mjs";

const exec = promisify(execFile);
const cli = new URL("../pilots/action-boundary/inspect-file-authority.mjs", import.meta.url).pathname;
const input = () => ({ tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a",
  audience: "mail-service", tool: "send_message", policy: { revision: 1 },
  preparedRequest: { to: "team@example.test", body: "Approved" } });

async function fixture(run) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-"));
  const directory = path.join(parent, "authority");
  const anchorDirectory = path.join(parent, "outside-anchor");
  try {
    const anchor = createFileAuthorityAnchor({ directory: anchorDirectory });
    const host = createFileRevocationHandoff({ directory, anchor });
    return await run({ parent, directory, anchorDirectory, anchor, host });
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
}

function snapshot(root) {
  const entries = [];
  function walk(directory) {
    for (const name of fs.readdirSync(directory).sort()) {
      const file = path.join(directory, name);
      const stat = fs.lstatSync(file);
      entries.push([path.relative(root, file), stat.mode, stat.size, stat.mtimeMs,
        stat.isFile() ? fs.readFileSync(file, "utf8") : null]);
      if (stat.isDirectory()) walk(file);
    }
  }
  walk(root);
  return entries;
}

test("inspection and its CLI report consistent protocol-3 state without writes", () =>
  fixture(async ({ parent, directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input(), { operationId: "host-intent-inspect-001" });
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => true })).status, "returned");
    assert.equal(host.revokeIssuer(input()).epoch, 1);
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory, anchor });
    const command = JSON.parse((await exec(process.execPath,
      [cli, directory, anchorDirectory])).stdout);
    assert.deepEqual([report.status, report.lock, report.checkpoints.comparison,
      report.committed_state.comparison], ["observed_consistent", "absent", "match", "match"]);
    assert.equal(report.anchor_lock, "absent");
    assert.equal(report.committed_state.includes_authority_mode, true);
    assert.deepEqual(report.authority_mode, { status: "valid", record: {
      protocol: "aml-file-authority-mode/1", mode: "checkpoint-anchored"
    } });
    assert.deepEqual(report.committed_state.counts,
      { epochs: 1, grants: 1, operations: 1, claimed: 1 });
    assert.deepEqual(report.reconciliation, {
      status: "no_unresolved_local_claims",
      counts: { claims: 1, outcomes: 1, returned: 1,
        missing_outcome: 0, unknown_outcome: 0 }, candidates: [], issues: []
    });
    assert.deepEqual(command, report);
    assert.deepEqual(snapshot(parent), before);
  }));

test("inspection cannot call an outcome resolved when a nested JSON key is ambiguous", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input());
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => "local-effect" })).status, "returned");
    const file = path.join(directory, "outcomes", `${grant.grant_id}.json`);
    const original = fs.readFileSync(file, "utf8");
    fs.writeFileSync(file, `{"metadata":{"\\u006bey":"first","key":"second"},${original.slice(1)}`);
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.committed_state.comparison, "match");
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reconciliation.issues.some(item =>
      item.grant_id === grant.grant_id && item.problem === "outcome_unreadable"));
  }));

test("inspection refuses outcome bytes that are not valid UTF-8", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input());
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => "local-effect" })).status, "returned");
    const file = path.join(directory, "outcomes", `${grant.grant_id}.json`);
    const original = fs.readFileSync(file, "utf8");
    fs.writeFileSync(file, Buffer.concat([
      Buffer.from('{"metadata":"'), Buffer.from([0xc3, 0x28]),
      Buffer.from(`",${original.slice(1)}`)
    ]));
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.committed_state.comparison, "match");
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reconciliation.issues.some(item =>
      item.grant_id === grant.grant_id && item.problem === "outcome_unreadable"));
  }));

test("a spent claim without an outcome is listed even when the lock is gone", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-claim-"));
  return (async () => {
    try {
      const directory = path.join(parent, "authority");
      const host = createFileRevocationHandoff({ directory, claimOnce: () => false });
      const grant = host.issue(input(), { operationId: "host-intent-review-001" });
      const result = await host.dispatch({ ...input(), grant_id: grant.grant_id,
        execute: () => { throw Error("unexpected callback"); } });
      assert.deepEqual([result.status, result.reason], ["blocked", "external_claim_spent"]);
      const before = snapshot(parent);
      const report = inspectFileRevocationHandoff({ directory });
      assert.equal(report.lock, "absent");
      assert.equal(report.committed_state.comparison, "not_committed");
      assert.equal(report.status, "needs_reconciliation");
      assert.ok(report.reasons.includes("claims_need_provider_review"));
      assert.equal(report.reconciliation.status, "provider_review_needed");
      assert.deepEqual(report.reconciliation.counts,
        { claims: 1, outcomes: 0, returned: 0, missing_outcome: 1,
          unknown_outcome: 0 });
      assert.deepEqual(report.reconciliation.candidates, [{ grant_id: grant.grant_id,
        operation_sha256: JSON.parse(fs.readFileSync(path.join(directory, "grants",
          `${grant.grant_id}.json`))).operation_sha256,
        idempotency_key_sha256: JSON.parse(fs.readFileSync(path.join(directory, "claimed",
          `${grant.grant_id}.json`))).idempotency_key_sha256,
        local_outcome: "missing" }]);
      assert.equal(JSON.stringify(report).includes("team@example.test"), false);
      assert.deepEqual(snapshot(parent), before);
    } finally { fs.rmSync(parent, { recursive: true, force: true }); }
  })();
});

test("unknown callback outcome and mismatched outcome are not called resolved", () =>
  fixture(async ({ parent, directory, anchor, host }) => {
    const grant = host.issue(input());
    const result = await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: async () => { throw Error("provider timeout"); } });
    assert.equal(result.status, "outcome_unknown");
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.checkpoints.comparison, "match");
    assert.equal(report.committed_state.comparison, "match");
    assert.equal(report.reconciliation.candidates[0].local_outcome, "outcome_unknown");
    assert.ok(report.reasons.includes("claims_need_provider_review"));
    assert.deepEqual(snapshot(parent), before);
    fs.writeFileSync(path.join(directory, "outcomes", `${grant.grant_id}.json`),
      JSON.stringify({ protocol: "aml-file-authority-outcome/1",
        grant_id: grant.grant_id, binding_sha256: "a".repeat(64),
        status: "returned", reason: "callback_returned" }) + "\n");
    const mismatched = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(mismatched.committed_state.comparison, "match");
    assert.equal(mismatched.reconciliation.status, "invalid_records");
    assert.ok(mismatched.reconciliation.issues.some(item =>
      item.problem === "outcome_invalid_or_mismatch"));
  }));

test("an outcome cannot claim return while recording a callback error", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input());
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => "local-effect" })).status, "returned");
    const file = path.join(directory, "outcomes", `${grant.grant_id}.json`);
    const outcome = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, JSON.stringify({ ...outcome, reason: "callback_error" }) + "\n");
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.committed_state.comparison, "match");
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reconciliation.issues.some(item =>
      item.grant_id === grant.grant_id && item.problem === "outcome_invalid_or_mismatch"));
  }));

test("unanchored inspection checks the spent operation epoch and issuer link", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-operation-"));
  return (async () => {
    try {
      const directory = path.join(parent, "authority");
      const host = createFileRevocationHandoff({ directory });
      const grant = host.issue(input(), { operationId: "host-intent-operation-link" });
      assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
        execute: () => "local-effect" })).status, "returned");
      const grantRecord = JSON.parse(fs.readFileSync(path.join(directory, "grants",
        `${grant.grant_id}.json`), "utf8"));
      const file = path.join(directory, "operations", `${grantRecord.operation_sha256}.json`);
      const operation = JSON.parse(fs.readFileSync(file, "utf8"));
      for (const altered of [{ ...operation, epoch: operation.epoch + 1 },
        { ...operation, issuer_sha256: "f".repeat(64) }]) {
        fs.writeFileSync(file, JSON.stringify(altered) + "\n");
        const report = inspectFileRevocationHandoff({ directory });
        assert.equal(report.committed_state.comparison, "not_committed");
        assert.equal(report.status, "needs_reconciliation");
        assert.ok(report.reconciliation.issues.some(item =>
          item.grant_id === grant.grant_id && item.problem === "operation_missing_or_mismatch"));
      }
      fs.writeFileSync(file, JSON.stringify(operation) + "\n");
      assert.equal(inspectFileRevocationHandoff({ directory }).status, "observed_consistent");
    } finally { fs.rmSync(parent, { recursive: true, force: true }); }
  })();
});

test("unanchored inspection reports an orphan operation marker before any claim", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-orphan-"));
  try {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(input(), { operationId: "host-intent-inspect-orphan" });
    fs.rmSync(path.join(directory, "grants", `${grant.grant_id}.json`));
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.committed_state.comparison, "not_committed");
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reasons.includes("reconciliation_records_invalid"));
    assert.ok(report.reconciliation.issues.some(item =>
      item.grant_id === grant.grant_id &&
      item.problem === "operation_without_matching_grant"));
    assert.equal(JSON.stringify(report).includes("team@example.test"), false);
    assert.deepEqual(snapshot(parent), before);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

test("unanchored inspection reports an unspent grant with a missing operation", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-unspent-"));
  try {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(input(), { operationId: "host-intent-inspect-unspent" });
    const operationName = fs.readdirSync(path.join(directory, "operations"))[0];
    fs.rmSync(path.join(directory, "operations", operationName));
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.reconciliation.counts.claims, 0);
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reconciliation.issues.some(item =>
      item.grant_id === grant.grant_id &&
      item.problem === "operation_missing_or_mismatch"));
    assert.deepEqual(snapshot(parent), before);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

test("unanchored inspection requires the grant to point back to its operation", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-backlink-"));
  try {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(input(), { operationId: "host-intent-inspect-backlink" });
    const grantFile = path.join(directory, "grants", `${grant.grant_id}.json`);
    const record = JSON.parse(fs.readFileSync(grantFile, "utf8"));
    delete record.operation_sha256;
    fs.writeFileSync(grantFile, JSON.stringify(record) + "\n");
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reconciliation.issues.some(item =>
      item.grant_id === grant.grant_id &&
      item.problem === "operation_without_matching_grant"));
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

test("unanchored inspection rejects a malformed issuer epoch", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-epoch-"));
  try {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    host.revokeIssuer(input());
    const epochFile = path.join(directory, "epochs",
      fs.readdirSync(path.join(directory, "epochs"))[0]);
    const epoch = JSON.parse(fs.readFileSync(epochFile, "utf8"));
    fs.writeFileSync(epochFile, JSON.stringify({ ...epoch, issuer_sha256: "a".repeat(64) }) + "\n");
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.committed_state.comparison, "not_committed");
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reconciliation.issues.some(item =>
      item.problem === "epoch_invalid"));
    assert.deepEqual(snapshot(parent), before);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

test("unanchored inspection reports a corrupt authority clock", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-clock-"));
  try {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    host.issue(input());
    fs.writeFileSync(path.join(directory, "clock.json"), JSON.stringify({
      protocol: "aml-file-authority-clock/1", time_ms: "not-a-time"
    }) + "\n");
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reasons.includes("authority_clock_invalid"));
    assert.deepEqual(snapshot(parent), before);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

test("unanchored inspection reports a missing clock after issuance", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-clock-loss-"));
  try {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    host.issue(input());
    fs.rmSync(path.join(directory, "clock.json"));
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reasons.includes("authority_clock_missing"));
    assert.deepEqual(snapshot(parent), before);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

test("an outcome with no spent claim is reported as an invalid local link", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input());
    fs.writeFileSync(path.join(directory, "outcomes", `${grant.grant_id}.json`),
      JSON.stringify({ protocol: "aml-file-authority-outcome/1",
        grant_id: grant.grant_id, binding_sha256: grant.binding_sha256,
        status: "returned", reason: "callback_returned" }) + "\n");
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.checkpoints.comparison, "match");
    assert.equal(report.committed_state.comparison, "match");
    assert.equal(report.reconciliation.status, "invalid_records");
    assert.deepEqual(report.reconciliation.issues,
      [{ grant_id: grant.grant_id, problem: "outcome_without_claim" }]);
    assert.ok(report.reasons.includes("reconciliation_records_invalid"));
  }));

test("a file anchor lock is visible even when both checkpoint records agree", () =>
  fixture(async ({ anchorDirectory, directory, anchor, host }) => {
    host.issue(input());
    fs.mkdirSync(path.join(anchorDirectory, "anchor.lock"), { mode: 0o700 });
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.deepEqual([report.status, report.lock, report.anchor_lock,
      report.checkpoints.comparison],
    ["needs_reconciliation", "absent", "present", "match"]);
    assert.ok(report.reasons.includes("external_anchor_lock_present"));
    assert.equal(fs.existsSync(path.join(anchorDirectory, "anchor.lock")), true);
  }));

test("a missing pinned authority mode is reported without recreating it", () =>
  fixture(async ({ directory, anchor, host }) => {
    host.issue(input());
    const modeFile = path.join(directory, "authority-mode.json");
    fs.rmSync(modeFile);
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.status, "needs_reconciliation");
    assert.equal(report.authority_mode.status, "missing");
    assert.ok(report.reasons.includes("authority_mode_missing"));
    assert.equal(fs.existsSync(modeFile), false);
  }));

test("a valid substituted mode disagrees with protocol-3 committed state", () =>
  fixture(async ({ directory, anchor, host }) => {
    host.issue(input());
    const modeFile = path.join(directory, "authority-mode.json");
    fs.writeFileSync(modeFile, JSON.stringify({ protocol: "aml-file-authority-mode/1",
      mode: "checkpoint-claim-anchored" }) + "\n");
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.authority_mode.status, "valid");
    assert.equal(report.checkpoints.comparison, "match");
    assert.equal(report.committed_state.comparison, "mismatch");
    assert.ok(report.reasons.includes("committed_state_mismatch"));
  }));

test("an empty local store with no mode is not called verified", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inspection-empty-"));
  try {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.status, "needs_reconciliation");
    assert.deepEqual(report.reasons, ["authority_mode_missing"]);
    assert.deepEqual(snapshot(parent), before);
    host.observeIssuer({ tenant: "tenant-a", issuer: "host-a" });
    assert.equal(inspectFileRevocationHandoff({ directory }).status, "observed_consistent");
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});

test("a present lock is reported without clearing it or authorizing another action", () =>
  fixture(async ({ parent, directory, anchorDirectory, anchor, host }) => {
    host.issue(input());
    fs.mkdirSync(path.join(directory, "authority.lock"), { mode: 0o700 });
    const before = snapshot(parent);
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.deepEqual([report.status, report.lock, report.reasons],
      ["needs_reconciliation", "present", ["authority_lock_present"]]);
    await assert.rejects(() => exec(process.execPath, [cli, directory, anchorDirectory]),
      error => error.code === 2 &&
        JSON.parse(error.stdout).reasons.includes("authority_lock_present"));
    assert.deepEqual(snapshot(parent), before);
    assert.throws(() => host.issue(input()), /authority_busy_or_crashed/);
  }));

test("selective epoch loss and an advanced outside checkpoint are distinguished", () =>
  fixture(async ({ directory, anchor, host }) => {
    host.issue(input());
    host.revokeIssuer(input());
    const epochFile = path.join(directory, "epochs", fs.readdirSync(path.join(directory,
      "epochs"))[0]);
    fs.rmSync(epochFile);
    const first = inspectFileRevocationHandoff({ directory, anchor });
    assert.deepEqual([first.checkpoints.comparison, first.committed_state.comparison],
      ["match", "mismatch"]);
    assert.ok(first.reasons.includes("committed_state_mismatch"));
    const old = anchor.read();
    assert.equal(anchor.compareAndSwap(old, { ...old, sequence: old.sequence + 1,
      head_sha256: "b".repeat(64) }), true);
    const second = inspectFileRevocationHandoff({ directory, anchor });
    assert.deepEqual([second.checkpoints.comparison, second.committed_state.comparison],
      ["mismatch", "mismatch"]);
    assert.ok(second.reasons.includes("checkpoint_mismatch"));
  }));

test("a malformed local checkpoint is identified without being called a missing one", () =>
  fixture(async ({ directory, anchor, host }) => {
    host.issue(input());
    fs.writeFileSync(path.join(directory, "checkpoint.json"), "{}\n");
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.equal(report.status, "needs_reconciliation");
    assert.equal(report.mode, "unknown");
    assert.ok(report.reasons.includes("local_checkpoint_invalid"));
    assert.equal(report.reasons.includes("local_checkpoint_missing"), false);
    assert.equal(report.reasons.includes("local_checkpoint_changed_during_inspection"), false);
  }));

test("a malformed outside checkpoint is reported distinctly from an unavailable one", () =>
  fixture(async ({ anchorDirectory, directory, anchor, host }) => {
    host.issue(input());
    fs.writeFileSync(path.join(anchorDirectory, "checkpoint.json"), "{}\n");
    const report = inspectFileRevocationHandoff({ directory, anchor });
    assert.ok(report.reasons.includes("external_checkpoint_invalid"));
    assert.equal(report.reasons.includes("external_checkpoint_unavailable"), false);
    assert.equal(report.reasons.includes("external_checkpoint_missing"), false);
  }));

test("a directory moved during inspection cannot be reported consistent", () =>
  fixture(async ({ parent, directory, anchor, host }) => {
    host.issue(input());
    let reads = 0;
    const movingAnchor = { read() {
      if (++reads === 2) fs.renameSync(directory, path.join(parent, "moved-authority"));
      return anchor.read();
    } };
    const report = inspectFileRevocationHandoff({ directory, anchor: movingAnchor });
    assert.equal(report.status, "needs_reconciliation");
    assert.ok(report.reasons.includes("authority_path_changed_during_inspection"));
  }));

test("inspection refuses unsafe paths and never creates a missing anchor", () =>
  fixture(async ({ parent, directory, anchor }) => {
    const missing = path.join(parent, "missing-anchor");
    assert.throws(() => createFileAuthorityAnchor({ directory: missing, create: false }),
      /ENOENT/);
    assert.equal(fs.existsSync(missing), false);
    const alias = path.join(parent, "authority-alias");
    fs.symlinkSync(directory, alias);
    assert.throws(() => inspectFileRevocationHandoff({ directory: alias, anchor }),
      /trusted_authority_path_required/);
    assert.throws(() => createFileRevocationHandoff({ directory,
      anchor: createFileAuthorityAnchor({ directory: parent, create: false }) }),
    /independent_anchor_directory_required/);
  }));
