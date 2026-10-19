import test from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createFileRevocationHandoff } from "../pilots/action-boundary/file-revocation-handoff.mjs";
import { createRevocablePreparedMailToolExecute } from "../pilots/action-boundary/revocable-prepared-mail-tool.mjs";
import { mailTargetResource } from "../pilots/action-boundary/mail-target-manifest.mjs";

const worker = new URL("../pilots/action-boundary/file-revocation-worker.mjs", import.meta.url).pathname;
const sendWorker = new URL("../pilots/action-boundary/revocable-mail-worker.mjs", import.meta.url).pathname;
const exec = promisify(execFile);
const input = () => ({ to: "team@example.test", subject: "Release", body: "Approved text" });
const policyFor = request => ({ protocol: "aml-action-policy/1", rules: [{
  tool: "send_message", effect: "send", resource: mailTargetResource(request).resource,
  requires_approval: true
}] });
const approved = async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 });
const make = (authority, options = {}) => createRevocablePreparedMailToolExecute({
  authority, tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a",
  audience: "mail-service", purpose: "Send release", getPolicy: () => policyFor(input()),
  operationIdFor: () => "host-intent-mail-001", prepare: async request => request,
  requestApproval: approved, execute: () => true,
  ...options
});
async function withDirectory(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-mail-handoff-"));
  try { return await run(directory, createFileRevocationHandoff({ directory })); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test("approved prepared request reaches one callback with a stable key and frozen fields", () =>
  withDirectory(async (_, authority) => {
    let sends = 0, observed;
    const send = make(authority, { execute: (request, { idempotencyKey }) => {
      sends++;
      observed = { request, idempotencyKey, frozen: Object.isFrozen(request) };
      return { accepted: true };
    } });
    const result = await send(input(), { modelContext: "must not reach sender" });
    assert.deepEqual([result.receipt.execution_status, result.dispatch_count, sends],
      ["dispatched", 1, 1]);
    assert.deepEqual(result.result, { accepted: true });
    assert.deepEqual(observed.request, input());
    assert.equal(observed.request.modelContext, undefined);
    assert.equal(observed.frozen, true);
    assert.match(observed.idempotencyKey, /^[a-f0-9]{64}$/);
  }));

test("one approval response cannot send the same host operation twice", () =>
  withDirectory(async (directory, authority) => {
    let sends = 0, operationId = "host-intent-mail-004";
    const send = make(authority, { operationIdFor: () => operationId,
      execute: () => { sends++; return { simulated: true }; } });
    assert.equal((await send(input())).receipt.execution_status, "dispatched");
    const repeated = await send(input());
    assert.deepEqual([repeated.receipt.reason, repeated.dispatch_count, sends],
      ["operation_already_claimed", 0, 1]);
    const changed = await send({ ...input(), body: "different text" });
    assert.deepEqual([changed.receipt.reason, changed.dispatch_count, sends],
      ["operation_payload_mismatch", 0, 1]);
    operationId = "host-intent-mail-005";
    assert.equal((await send(input())).receipt.execution_status, "dispatched");
    assert.equal(sends, 2);
    assert.equal(fs.readdirSync(path.join(directory, "operations")).length, 2);
  }));

test("two real workers competing for one intent produce at most one send", () =>
  withDirectory(async directory => {
    const results = await Promise.all([0, 1].map(() => exec(process.execPath,
      [sendWorker, directory, "host-intent-shared-006"])));
    const rows = results.map(result => JSON.parse(result.stdout));
    assert.equal(rows.filter(row => row.dispatch_count === 1).length, 1);
    assert.equal(rows.filter(row => row.dispatch_count === 0).length, 1);
    assert.equal(fs.readFileSync(path.join(directory, "effects.log"), "utf8"), "send\n");
    const again = JSON.parse((await exec(process.execPath,
      [sendWorker, directory, "host-intent-shared-006"])).stdout);
    assert.deepEqual([again.reason, again.dispatch_count], ["operation_already_claimed", 0]);
  }));

test("host-added BCC without an exact rule cannot be approved or sent", () =>
  withDirectory(async (_, authority) => {
    let approvals = 0, sends = 0;
    const send = make(authority, { prepare: request => ({ ...request, bcc: ["other@example.test"] }),
      requestApproval: () => { approvals++; return approved; }, execute: () => { sends++; } });
    const result = await send(input());
    assert.deepEqual([result.receipt.reason, result.dispatch_count, approvals, sends],
      ["no_exact_rule", 0, 0, 0]);
  }));

test("approval must bind the prepared content; policy replacement blocks after approval", () =>
  withDirectory(async (_, authority) => {
    let sends = 0, policy = policyFor(input());
    const changed = make(authority, { prepare: request => ({ ...request, body: "New text" }),
      getPolicy: () => policyFor(input()), requestApproval: async ({ proposal }) => {
        assert.equal(proposal.arguments.body, "New text");
        return { approved: true, proposal_sha256: "0".repeat(64) };
      }, execute: () => { sends++; } });
    // A matching recipient rule allows the proposal, but the mismatched
    // approval digest must stop its changed body.
    assert.equal((await changed(input())).receipt.reason, "approval_missing_or_mismatched");
    const send = make(authority, { getPolicy: () => policy,
      requestApproval: async arg => { policy = { protocol: "aml-action-policy/1", rules: [] };
        return approved(arg); }, execute: () => { sends++; } });
    assert.equal((await send(input())).receipt.reason, "policy_changed");
    assert.equal(sends, 0);
  }));

test("a second process revoking during awaited approval blocks the provider callback", () =>
  withDirectory(async (directory, authority) => {
    let release, entered;
    const pending = new Promise(resolve => { release = resolve; });
    const waiting = new Promise(resolve => { entered = resolve; });
    let sends = 0, approveInput;
    const send = make(authority, { requestApproval: async arg => {
      approveInput = arg;
      entered();
      await pending;
      return approved(arg);
    }, execute: () => { sends++; } });
    const action = send(input());
    await waiting;
    const revocation = JSON.parse(execFileSync(process.execPath,
      [worker, directory, "unused", "revoke"], { encoding: "utf8" }));
    assert.equal(revocation.epoch, 1);
    assert.equal(fs.readdirSync(path.join(directory, "grants")).length, 0);
    assert.equal(approveInput.proposal.arguments.to, "team@example.test");
    release();
    const result = await action;
    assert.deepEqual([result.receipt.execution_status, result.receipt.reason,
      result.dispatch_count, sends], ["blocked", "issuer_revoked", 0, 0]);
  }));

test("revocation immediately after approval also blocks; rejected grants cannot replay", () =>
  withDirectory(async (directory, authority) => {
    let sends = 0, reserved;
    const guardedAuthority = {
      observeIssuer: identity => authority.observeIssuer(identity),
      issue(binding, options) {
        reserved = { binding, grant: authority.issue(binding, options) };
        execFileSync(process.execPath, [worker, directory, "unused", "revoke"]);
        return reserved.grant;
      },
      dispatch: action => authority.dispatch(action)
    };
    const send = make(guardedAuthority, { execute: () => { sends++; } });
    const outcome = await send(input());
    assert.deepEqual([outcome.receipt.reason, outcome.dispatch_count, sends],
      ["issuer_revoked", 0, 0]);
    const replay = await authority.dispatch({ ...reserved.binding, grant_id: reserved.grant.grant_id,
      execute: () => { sends++; } });
    assert.equal(replay.reason, "issuer_revoked");
    assert.equal(sends, 0);
  }));

test("expiry, denial, invalid preparation, and callback uncertainty fail closed", () =>
  withDirectory(async directory => {
    let time = 1000, sends = 0;
    // A separate instance uses the same disk and a controllable host clock.
    const authority = createFileRevocationHandoff({ directory, now: () => time });
    const advancingAuthority = { observeIssuer: identity => authority.observeIssuer(identity),
      issue(binding, options) { const grant = authority.issue(binding, options); time += 10; return grant; },
      dispatch: action => authority.dispatch(action) };
    const expired = make(advancingAuthority, { ttlMs: 10,
      execute: () => { sends++; } });
    assert.equal((await expired(input())).receipt.reason, "grant_expired_or_clock_invalid");
    const denied = make(authority, { getPolicy: () => ({ protocol: "aml-action-policy/1",
      rules: [{ ...policyFor(input()).rules[0], requires_approval: false }] }),
      execute: () => { sends++; } });
    assert.equal((await denied(input())).receipt.reason, "approval_required_rule");
    const invalid = make(authority, { prepare: request => ({ ...request, hiddenRoute: "other@example.test" }),
      execute: () => { sends++; } });
    await assert.rejects(invalid(input()), /unsupported_mail_arguments/);
    time = 1011;
    const uncertain = make(authority, { operationIdFor: () => "host-intent-uncertain-002",
      execute: () => { sends++; throw Error("timeout"); } });
    const outcome = await uncertain(input());
    assert.deepEqual([outcome.receipt.execution_status, outcome.dispatch_count, sends],
      ["unknown", 1, 1]);
    const retry = await uncertain(input());
    assert.deepEqual([retry.receipt.reason, retry.dispatch_count, sends],
      ["operation_already_claimed", 0, 1]);
  }));

test("a malformed authority observation or outcome cannot report a successful send", () =>
  withDirectory(async (_, authority) => {
    let approvals = 0, sends = 0;
    const noEpoch = make({ observeIssuer: () => ({}), issue: () => { throw Error("must not issue"); },
      dispatch: () => { throw Error("must not dispatch"); } },
    { requestApproval: arg => { approvals++; return approved(arg); }, execute: () => { sends++; } });
    assert.equal((await noEpoch(input())).receipt.reason, "authority_observation_unavailable");
    assert.equal(approvals, 0);
    const malformed = make({ observeIssuer: identity => authority.observeIssuer(identity),
      issue: (binding, options) => authority.issue(binding, options),
      dispatch: () => ({ status: "returned", reason: "callback_returned", dispatch_count: 0 }) },
    { execute: () => { sends++; } });
    const result = await malformed(input());
    assert.deepEqual([result.receipt.execution_status, result.dispatch_count, sends],
      ["unknown", null, 0]);
  }));
