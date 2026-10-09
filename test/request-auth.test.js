import test from "node:test";
import assert from "node:assert/strict";
import { createRequestAuthenticator } from "../server/requestAuth.js";

const token = "0123456789abcdef0123456789abcdef0123456789abcdef";
const request = (header, rawHeaders = ["Authorization", header]) => ({
  headers: { authorization: header }, rawHeaders
});

test("bearer guard accepts the configured token and rejects substitutes", async () => {
  const authorize = createRequestAuthenticator({ bearer_token: token });
  await authorize(request(`Bearer ${token}`));
  await authorize(request(`bearer   ${token}`));
  await assert.rejects(authorize(request(`Bearer ${token.slice(0, -1)}0`)), {
    message: "unauthorized", statusCode: 401
  });
  await assert.rejects(authorize(request("Basic anything")), { statusCode: 401 });
  await assert.rejects(authorize(request(`Bearer ${token}=bad`)), { statusCode: 401 });
  await assert.rejects(authorize(request(`Bearer\t${token}`)), { statusCode: 401 });
  await assert.rejects(authorize(request(undefined, [])), { statusCode: 401 });
  await assert.rejects(authorize(request(`Bearer ${token}`, [
    "Authorization", `Bearer ${token}`, "authorization", "Bearer replacement"
  ])), { statusCode: 401 });
});

test("bearer guard accepts padded base64 tokens", async () => {
  const padded = `${token}==`;
  const authorize = createRequestAuthenticator({ bearer_token: padded });
  await authorize(request(`Bearer ${padded}`));
});

test("callback guard requires explicit true and masks internal failures", async () => {
  const authorize = createRequestAuthenticator(async () => true);
  await authorize(request(undefined, []));
  const denied = createRequestAuthenticator(async () => ({ user: "unverified" }));
  await assert.rejects(denied(request(undefined, [])), {
    message: "unauthorized", statusCode: 401
  });
  const unavailable = createRequestAuthenticator(async () => { throw new Error("private identity error"); });
  await assert.rejects(unavailable(request(undefined, [])), {
    message: "authentication_unavailable", statusCode: 503
  });
});

test("callback guard bounds stalled authentication and signals cancellation", async () => {
  let signal;
  const authorize = createRequestAuthenticator(async (_req, controls) => {
    signal = controls.signal;
    return new Promise(() => {});
  }, { timeout_ms: 10 });
  await assert.rejects(authorize(request(undefined, [])), {
    message: "authentication_unavailable", statusCode: 503
  });
  assert.equal(signal.aborted, true);
  assert.throws(() => createRequestAuthenticator(null, { timeout_ms: 0 }), /auth_timeout_ms/);
});

test("weak or malformed authentication configuration fails at startup", () => {
  assert.throws(() => createRequestAuthenticator({ bearer_token: "short" }), /32-4096/);
  assert.throws(() => createRequestAuthenticator({ bearer_token: token, typo: true }), /request_auth/);
  assert.throws(() => createRequestAuthenticator({ bearer_token: `${token}\n` }), /ASCII bearer-token/);
  assert.throws(() => createRequestAuthenticator({ bearer_token: `${token}é` }), /ASCII bearer-token/);
  assert.throws(() => createRequestAuthenticator({ bearer_token: `${token}:suffix` }), /ASCII bearer-token/);
});
