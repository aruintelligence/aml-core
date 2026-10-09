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
  await assert.rejects(authorize(request(`Bearer ${token.slice(0, -1)}0`)), {
    message: "unauthorized", statusCode: 401
  });
  await assert.rejects(authorize(request("Basic anything")), { statusCode: 401 });
  await assert.rejects(authorize(request(undefined, [])), { statusCode: 401 });
  await assert.rejects(authorize(request(`Bearer ${token}`, [
    "Authorization", `Bearer ${token}`, "authorization", "Bearer replacement"
  ])), { statusCode: 401 });
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

test("weak or malformed authentication configuration fails at startup", () => {
  assert.throws(() => createRequestAuthenticator({ bearer_token: "short" }), /32-4096/);
  assert.throws(() => createRequestAuthenticator({ bearer_token: token, typo: true }), /request_auth/);
  assert.throws(() => createRequestAuthenticator({ bearer_token: `${token}\n` }), /non-whitespace/);
});
