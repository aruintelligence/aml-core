// Release-blocker regression: js/file-access-to-http at runtime/lockedHttpRenderGate.js.
// The bearer token and intent must not leave the process over cleartext to a
// non-loopback address, through a redirect, or through an environment proxy.
// Synthetic canaries only; every server binds to a loopback literal.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { once } from "node:events";
import { execFile, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evaluateLockedHttpAndRender } from "../index.js";

const run = promisify(execFile);
const INDEX = fileURLToPath(new URL("../index.js", import.meta.url));
const TOKEN = "SYNTHETIC_BEARER_CANARY_7d41";
const INTENT = { proposal: "SYNTHETIC_INTENT_CANARY_9b02" };
const PINS = ["0".repeat(64)];

function call(url, fetchImpl) {
  return evaluateLockedHttpAndRender({ url, token: TOKEN, intent: INTENT, profile: "human_first",
    context: {}, trustedReceiptFingerprints: PINS, timeoutMs: 3000,
    render: async () => { throw new Error("must not render"); },
    ...(fetchImpl ? { fetchImpl } : {}) });
}

function spy() {
  const calls = [];
  const fetchImpl = async (href, init) => { calls.push({ href, init }); return { status: 503, headers: new Headers() }; };
  return { calls, fetchImpl };
}

function assertNoCanary(value) {
  const text = JSON.stringify(value);
  assert.ok(!text.includes("CANARY"), "result must not echo token, intent or URL credentials");
}

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}

function capture(seen, name) {
  return (req, res) => {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => {
      seen.push({ name, auth: String(req.headers.authorization ?? "").includes("CANARY"),
        body: body.includes("CANARY") });
      res.writeHead(500); res.end();
    });
  };
}

function close(...servers) {
  for (const server of servers) { server.closeAllConnections?.(); server.close(); }
}

test("cleartext, name-based, wildcard, mapped and non-http destinations are refused before any fetch", async () => {
  const cases = [
    "http://192.0.2.10/v1/deployment/evaluate",
    "http://example.test/v1/deployment/evaluate",
    "http://localhost:8787/v1/deployment/evaluate",
    "http://LOCALHOST./v1/deployment/evaluate",
    "http://127.0.0.1.nip.io/v1/deployment/evaluate",
    "http://0.0.0.0:8787/v1/deployment/evaluate",
    "http://[::ffff:127.0.0.1]:8787/v1/deployment/evaluate",
    "http://[::]:8787/v1/deployment/evaluate",
    "http://10.0.0.1/v1/deployment/evaluate",
    "ws://127.0.0.1:8787/", "ftp://127.0.0.1/", "file:///etc/hostname",
    "data:application/json,%7B%7D", "not a url", ""
  ];
  for (const url of cases) {
    const { calls, fetchImpl } = spy();
    const result = await call(url, fetchImpl);
    assert.equal(result.status, "blocked", url);
    assert.match(result.reason, /^(insecure_evaluation_url|invalid_evaluation_url)$/, url);
    assert.equal(calls.length, 0, `${url} must be refused before the token leaves the process`);
    assertNoCanary(result);
  }
  for (const url of [undefined, null, 42, {}]) {
    const { calls, fetchImpl } = spy();
    assert.equal((await call(url, fetchImpl)).reason, "invalid_evaluation_url");
    assert.equal(calls.length, 0);
  }
});

test("loopback literals stay compatible and are sent in WHATWG-normalized form", async () => {
  const cases = [
    ["http://127.0.0.1:8787/v1/deployment/evaluate", "http://127.0.0.1:8787/v1/deployment/evaluate"],
    ["http://127.0.0.2:8787/x", "http://127.0.0.2:8787/x"],
    ["http://127.255.255.254/x", "http://127.255.255.254/x"],
    ["http://2130706433:8787/x", "http://127.0.0.1:8787/x"],
    ["http://0x7f.1:8787/x", "http://127.0.0.1:8787/x"],
    ["http://0177.0.0.1:8787/x", "http://127.0.0.1:8787/x"],
    ["http://[::1]:8787/x", "http://[::1]:8787/x"],
    ["http://[0:0:0:0:0:0:0:1]:8787/x", "http://[::1]:8787/x"],
    ["https://aml.example.test/v1/deployment/evaluate", "https://aml.example.test/v1/deployment/evaluate"],
    ["https://192.0.2.10:8443/x", "https://192.0.2.10:8443/x"]
  ];
  for (const [url, expected] of cases) {
    const { calls, fetchImpl } = spy();
    const result = await call(url, fetchImpl);
    assert.equal(result.reason, "http_evaluation_unavailable", url);
    assert.equal(calls.length, 1, url);
    assert.equal(calls[0].href, expected);
    assert.equal(calls[0].init.redirect, "error");
    assert.equal(calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
  }
  const { calls, fetchImpl } = spy();
  await call(new URL("http://127.0.0.1:8787/x"), fetchImpl);
  assert.equal(calls.length, 1, "URL objects remain accepted");
});

test("URL userinfo is refused for every scheme and never echoed", async () => {
  for (const url of ["https://user:SYNTHETIC_PASSWORD_CANARY@aml.example.test/x",
    "https://SYNTHETIC_USER_CANARY@aml.example.test/x", "http://u:SYNTHETIC_CANARY@127.0.0.1:8787/x"]) {
    const { calls, fetchImpl } = spy();
    const result = await call(url, fetchImpl);
    assert.equal(result.reason, "evaluation_url_credentials");
    assert.equal(calls.length, 0);
    assertNoCanary(result);
  }
});

test("a real cross-origin or same-origin redirect never re-sends the token or intent", async () => {
  const seen = [];
  const sink = http.createServer(capture(seen, "redirect_target"));
  const sinkPort = await listen(sink);
  const redirector = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push({ name: "configured_endpoint" });
      const location = req.url === "/same" ? `/collect` : `http://127.0.0.2:${sinkPort}/collect`;
      res.writeHead(req.url === "/permanent" ? 308 : 307, { location }); res.end();
    });
  });
  const port = await listen(redirector);
  try {
    for (const route of ["/cross", "/same", "/permanent"]) {
      const result = await call(`http://127.0.0.1:${port}${route}`);
      assert.equal(result.status, "blocked");
      assert.equal(result.reason, "redirect_refused", route);
      assertNoCanary(result);
    }
    assert.deepEqual(seen.map(item => item.name),
      ["configured_endpoint", "configured_endpoint", "configured_endpoint"]);
  } finally { close(sink, redirector); }
});

test("custom transports that follow redirects or return 3xx are refused", async () => {
  const followed = await call("https://aml.example.test/x", async () => ({ status: 200, redirected: true,
    headers: new Headers(), body: new Response("{}").body }));
  assert.equal(followed.reason, "redirect_refused");
  const status = await call("https://aml.example.test/x", async () => ({ status: 302, headers: new Headers() }));
  assert.equal(status.reason, "redirect_refused");
});

function makeCertificate(dir) {
  const key = path.join(dir, "key.pem");
  const cert = path.join(dir, "cert.pem");
  // An empty configuration keeps the fixture independent of the host's openssl.cnf.
  const config = path.join(dir, "openssl.cnf");
  writeFileSync(config, "");
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
    "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1"],
    { stdio: "ignore", env: { PATH: process.env.PATH ?? "", OPENSSL_CONF: config } });
  return { key: readFileSync(key), cert: readFileSync(cert), certPath: cert };
}

const CHILD = `const { evaluateLockedHttpAndRender } = await import(process.env.AML_INDEX);
const result = await evaluateLockedHttpAndRender({ url: process.env.AML_URL,
  token: "SYNTHETIC_BEARER_CANARY_7d41", intent: { proposal: "SYNTHETIC_INTENT_CANARY_9b02" },
  profile: "human_first", context: {}, trustedReceiptFingerprints: ["0".repeat(64)], timeoutMs: 3000,
  render: async () => { throw new Error("must not render"); } });
process.stdout.write(JSON.stringify(result));`;

function childEnv(extra) {
  return { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", AML_INDEX: INDEX, ...extra };
}

test("an https endpoint redirecting to http (downgrade) never re-sends the intent in cleartext", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "aml-tls-"));
  const seen = [];
  const plain = http.createServer(capture(seen, "http_downgrade_target"));
  try {
    const { key, cert, certPath } = makeCertificate(dir);
    const plainPort = await listen(plain);
    const secure = https.createServer({ key, cert }, (req, res) => {
      req.resume();
      req.on("end", () => {
        seen.push({ name: "https_endpoint", auth: String(req.headers.authorization ?? "").includes("CANARY") });
        res.writeHead(307, { location: `http://127.0.0.1:${plainPort}/collect` }); res.end();
      });
    });
    const securePort = await listen(secure);
    try {
      const { stdout } = await run(process.execPath, ["--input-type=module", "-e", CHILD], {
        env: childEnv({ AML_URL: `https://127.0.0.1:${securePort}/v1/deployment/evaluate`,
          NODE_EXTRA_CA_CERTS: certPath }), timeout: 20000 });
      const result = JSON.parse(stdout);
      assert.equal(result.reason, "redirect_refused");
      assert.deepEqual(seen, [{ name: "https_endpoint", auth: true }],
        "TLS endpoint received the request; the cleartext target received nothing");
    } finally { close(secure); }
  } finally { close(plain); rmSync(dir, { recursive: true, force: true }); }
});

test("Node environment proxies cannot carry the cleartext loopback exchange", async () => {
  const seen = [];
  const target = http.createServer(capture(seen, "loopback_target"));
  const targetPort = await listen(target);
  const proxy = http.createServer((req, res) => { req.resume(); seen.push({ name: "proxy_request" }); res.writeHead(502); res.end(); });
  proxy.on("connect", (req, socket) => { seen.push({ name: "proxy_connect" }); socket.destroy(); });
  const proxyPort = await listen(proxy);
  const url = `http://127.0.0.1:${targetPort}/v1/deployment/evaluate`;
  const proxyEnv = { HTTP_PROXY: `http://127.0.0.1:${proxyPort}`, HTTPS_PROXY: `http://127.0.0.1:${proxyPort}` };
  try {
    for (const enable of [{ NODE_USE_ENV_PROXY: "1" }, { NODE_OPTIONS: "--use-env-proxy" },
      { NODE_USE_ENV_PROXY: "true", NO_PROXY: "127.0.0.1" }]) {
      seen.length = 0;
      const { stdout } = await run(process.execPath, ["--input-type=module", "-e", CHILD], {
        env: childEnv({ AML_URL: url, ...proxyEnv, ...enable }), timeout: 20000 });
      assert.equal(JSON.parse(stdout).reason, "cleartext_proxy_refused", JSON.stringify(enable));
      assert.deepEqual(seen, [], "neither the proxy nor the target received any byte");
    }
    // Proxy variables alone do not change Node's built-in fetch, so the direct
    // loopback exchange stays compatible and the proxy sees nothing.
    seen.length = 0;
    const { stdout } = await run(process.execPath, ["--input-type=module", "-e", CHILD], {
      env: childEnv({ AML_URL: url, ...proxyEnv }), timeout: 20000 });
    assert.equal(JSON.parse(stdout).reason, "http_evaluation_unavailable");
    assert.deepEqual(seen.map(item => item.name), ["loopback_target"]);
  } finally { close(target, proxy); }
});

test("https destinations remain allowed when an environment proxy is configured", async () => {
  const saved = { ...process.env };
  try {
    process.env.NODE_USE_ENV_PROXY = "1";
    process.env.HTTP_PROXY = "http://127.0.0.1:9";
    process.env.HTTPS_PROXY = "http://127.0.0.1:9";
    const { calls, fetchImpl } = spy();
    assert.equal((await call("https://aml.example.test/x", fetchImpl)).reason, "http_evaluation_unavailable");
    assert.equal(calls.length, 1);
    const blockedCleartext = spy();
    assert.equal((await call("http://127.0.0.1:8787/x", blockedCleartext.fetchImpl)).reason,
      "cleartext_proxy_refused");
    assert.equal(blockedCleartext.calls.length, 0, "custom transports are held to the same rule");
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
  }
});
