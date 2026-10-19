import test from "node:test";
import assert from "node:assert/strict";
import { createLocalRevocationHandoff } from "../pilots/action-boundary/local-revocation-handoff.mjs";

function context() {
  return {
    tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a", audience: "mail-service",
    tool: "send_mail", policy: { allowed: ["send_mail"], revision: 1 },
    preparedRequest: { to: ["team@example.test"], bcc: [], subject: "Update", body: "Approved" }
  };
}

test("one synchronous handoff wins simultaneous consumes; its callback sees frozen approved bytes", async () => {
  const host = createLocalRevocationHandoff();
  const input = context();
  const grant = host.issue(input);
  const effects = [];
  let release;
  const deferred = new Promise(resolve => { release = resolve; });
  const execute = (request, { idempotencyKey }) => {
    effects.push({ request, idempotencyKey });
    return deferred;
  };
  const firstAttempt = host.dispatch({ ...input, grant_id: grant.grant_id, execute });
  const secondAttempt = host.dispatch({ ...input, grant_id: grant.grant_id, execute });
  assert.equal(effects.length, 1, "handoff begins before the first await");
  release({ accepted: true });
  const [first, second] = await Promise.all([firstAttempt, secondAttempt]);
  assert.equal(first.status, "returned");
  assert.equal(second.status, "blocked");
  assert.equal(second.reason, "grant_missing_or_spent");
  assert.equal(effects.length, 1);
  assert.deepEqual(effects[0].request, input.preparedRequest);
  assert.match(effects[0].idempotencyKey, /^[a-f0-9]{64}$/);
});

test("revocation before handoff blocks, while a different tenant stays independent", async () => {
  const host = createLocalRevocationHandoff();
  const a = context();
  const b = { ...context(), tenant: "tenant-b" };
  const grantA = host.issue(a);
  const grantB = host.issue(b);
  host.revokeIssuer({ tenant: a.tenant, issuer: a.issuer });
  let calls = 0;
  const execute = () => { calls++; return true; };
  assert.equal((await host.dispatch({ ...a, grant_id: grantA.grant_id, execute })).reason, "issuer_revoked");
  assert.equal((await host.dispatch({ ...b, grant_id: grantB.grant_id, execute })).status, "returned");
  assert.equal(calls, 1);
});

test("identity, policy, and exact prepared request remain bound without consuming on mismatch", async () => {
  const host = createLocalRevocationHandoff();
  const input = context();
  const grant = host.issue(input);
  let calls = 0;
  const execute = () => { calls++; return true; };
  for (const change of [
    { tenant: "tenant-b" }, { actor: "reviewer-b" }, { audience: "other-service" },
    { tool: "other-tool" }, { policy: { allowed: ["send_mail"], revision: 2 } },
    { preparedRequest: { ...input.preparedRequest, bcc: ["outside@example.test"] } }
  ]) {
    const denied = await host.dispatch({ ...input, ...change, grant_id: grant.grant_id, execute });
    assert.deepEqual([denied.status, denied.reason, denied.dispatch_count],
      ["blocked", "binding_mismatch", 0]);
  }
  assert.equal(calls, 0);
  const accepted = await host.dispatch({ ...input, grant_id: grant.grant_id, execute });
  assert.equal(accepted.status, "returned");
  assert.equal(calls, 1);
});

test("host clock expiry and rollback fail closed without a callback", async () => {
  let time = 1000;
  const host = createLocalRevocationHandoff({ now: () => time });
  const input = context();
  const grant = host.issue(input, { ttlMs: 100 });
  let calls = 0;
  const execute = () => { calls++; };
  time = 1100;
  assert.equal((await host.dispatch({ ...input, grant_id: grant.grant_id, execute })).reason, "grant_expired");
  time = 1101;
  const second = host.issue(input);
  time = 900;
  assert.equal((await host.dispatch({ ...input, grant_id: second.grant_id, execute })).reason,
    "authority_input_or_clock_invalid");
  assert.equal(calls, 0);
});

test("caller time cannot backdate a grant and a failed host clock blocks before handoff", async () => {
  let time = 1000;
  const host = createLocalRevocationHandoff({ now: () => time });
  const input = context();
  const grant = host.issue(input, { ttlMs: 20 });
  let calls = 0;
  time = 1020;
  const execute = () => { calls++; return true; };
  const backdated = await host.dispatch({ ...input, grant_id: grant.grant_id,
    now: 1001, execute });
  assert.equal(backdated.reason, "grant_expired");
  time = 1021;
  const second = host.issue(input);
  time = NaN;
  const unavailable = await host.dispatch({ ...input, grant_id: second.grant_id, execute });
  assert.deepEqual([unavailable.status, unavailable.reason, unavailable.dispatch_count],
    ["blocked", "authority_input_or_clock_invalid", 0]);
  assert.equal(calls, 0);
});

test("uncertain callback outcome stays spent; revocation inside callback is after local handoff", async () => {
  const host = createLocalRevocationHandoff();
  const input = context();
  const grant = host.issue(input);
  let calls = 0;
  const execute = () => {
    calls++;
    host.revokeIssuer({ tenant: input.tenant, issuer: input.issuer });
    throw Error("provider outcome unknown");
  };
  const first = await host.dispatch({ ...input, grant_id: grant.grant_id, execute });
  assert.deepEqual([first.status, first.dispatch_count], ["outcome_unknown", 1]);
  const replay = await host.dispatch({ ...input, grant_id: grant.grant_id, execute });
  assert.deepEqual([replay.reason, replay.dispatch_count], ["grant_missing_or_spent", 0]);
  assert.equal(calls, 1);
});

test("a rejected asynchronous provider result is unknown and never retried", async () => {
  const host = createLocalRevocationHandoff();
  const input = context();
  const grant = host.issue(input);
  let calls = 0;
  const execute = async () => { calls++; throw Error("timeout after handoff"); };
  const first = await host.dispatch({ ...input, grant_id: grant.grant_id, execute });
  assert.equal(first.status, "outcome_unknown");
  assert.equal((await host.dispatch({ ...input, grant_id: grant.grant_id, execute })).status, "blocked");
  assert.equal(calls, 1);
});
