import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import http from "node:http";
import { once } from "node:events";
import { closeSync, openSync, readFileSync, readSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { createAmlHttpServer, evaluateLockedHttpAndRender } from "../../index.js";
import { readJson } from "../../server/readJson.js";

const fixture = name => JSON.parse(readFileSync(new URL(name, import.meta.url), "utf8"));
const demoIntents = Object.freeze({
  allowed: fixture("intent-allowed.json"),
  sensitive: fixture("intent-sensitive.json")
});
const demoContext = JSON.parse(readFileSync(new URL("../enterprise-30min/context-denied.json", import.meta.url), "utf8"));
const profile = "human_first";
const assets = Object.freeze({
  "/": ["index.html", "text/html; charset=utf-8"],
  "/screen.js": ["screen.js", "text/javascript; charset=utf-8"],
  "/screen.css": ["screen.css", "text/css; charset=utf-8"]
});
const securityHeaders = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY"
};

function send(res, status, data, contentType = "application/json; charset=utf-8") {
  const body = typeof data === "string" ? data : JSON.stringify(data);
  res.writeHead(status, { ...securityHeaders, "content-type": contentType,
    "content-length": Buffer.byteLength(body) });
  res.end(body);
}

async function listen(server, port) {
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
}

async function stop(server) {
  if (server.listening) await new Promise((done, reject) => server.close(error => error ? reject(error) : done()));
}

function readBoundedJsonFile(path, maxBytes) {
  const fd = openSync(path, "r");
  try {
    const bytes = Buffer.alloc(maxBytes + 1);
    let size = 0;
    while (size < bytes.length) {
      const count = readSync(fd, bytes, size, bytes.length - size, null);
      if (count === 0) break;
      size += count;
    }
    if (size > maxBytes) throw new Error("scenario file too large");
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, size)));
  } finally { closeSync(fd); }
}

const plainObject = value => value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

export function loadScenarioFiles(intentPath, contextPath) {
  if (typeof intentPath !== "string" || !intentPath ||
      typeof contextPath !== "string" || !contextPath) {
    throw new TypeError("provide both --intent and --context files");
  }
  const intent = readBoundedJsonFile(intentPath, 64 * 1024);
  const context = readBoundedJsonFile(contextPath, 16 * 1024);
  if (!plainObject(intent) || typeof intent.transmission !== "string" ||
      !Array.isArray(intent.nodes) || intent.nodes.length < 1 || intent.nodes.length > 20 ||
      !plainObject(context)) {
    throw new TypeError("scenario must have a transmission, 1–20 nodes, and an object context");
  }
  return { intent, context };
}

export async function startScreenPilot({ port = 4173, scenario = null } = {}) {
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new TypeError("invalid port");
  if (scenario !== null && (!plainObject(scenario) || !plainObject(scenario.intent) ||
      !plainObject(scenario.context))) throw new TypeError("scenario requires intent and context objects");
  // Snapshot host inputs before listening. The browser can select only a name.
  const intents = scenario ? Object.freeze({ custom: structuredClone(scenario.intent) }) : demoIntents;
  const context = scenario ? structuredClone(scenario.context) : demoContext;
  const mode = scenario ? "custom" : "demo";
  // Demonstration credentials are ephemeral and never leave this Node process.
  const token = randomBytes(32).toString("hex");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const trustedReceiptFingerprints = [createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" })).digest("hex")];
  const amlServer = createAmlHttpServer({
    request_auth: { bearer_token: token },
    locked_policy: { profile, mode: "enforce", failure_mode: "closed", context },
    receipt_signing: { private_key_pem: privateKeyPem, signer: "localhost-screen-pilot" }
  });
  let screenServer;
  try {
    await listen(amlServer, 0);
    const url = `http://127.0.0.1:${amlServer.address().port}/v1/deployment/evaluate`;
    screenServer = http.createServer(async (req, res) => {
      const path = new URL(req.url || "/", "http://localhost").pathname;
      if (req.method === "GET" && Object.hasOwn(assets, path)) {
        const [file, contentType] = assets[path];
        return send(res, 200, readFileSync(new URL(file, import.meta.url), "utf8"), contentType);
      }
      if (req.method === "GET" && path === "/api/info") {
        return send(res, 200, { mode });
      }
      if (req.method !== "POST" || path !== "/api/evaluate") {
        return send(res, 404, { error: "not_found" });
      }
      if (req.headers["content-type"] !== "application/json") {
        return send(res, 415, { error: "json_required" });
      }
      let body;
      try { body = await readJson(req, 1024); }
      catch (error) {
        return send(res, error.statusCode ?? 400, { error: "invalid_request" });
      }
      // The browser selects a named example, never an intent or policy override.
      if (!body || typeof body !== "object" || Array.isArray(body) ||
          Object.keys(body).length !== 1 || typeof body.fixture !== "string" ||
          !Object.hasOwn(intents, body.fixture)) {
        return send(res, 400, { error: "unknown_fixture" });
      }
      let verifiedHtml;
      const gate = await evaluateLockedHttpAndRender({
        url, token, profile, context, intent: intents[body.fixture], trustedReceiptFingerprints,
        render: html => { verifiedHtml = html; }
      });
      if (gate.status !== "rendered") {
        return send(res, 200, { decision: "blocked", reason: gate.reason,
          receipt_sha256: gate.receipt_sha256 });
      }
      return send(res, 200, { decision: "allow", reason: gate.reason,
        receipt_sha256: gate.receipt_sha256, html: verifiedHtml });
    });
    await listen(screenServer, port);
    return { url: `http://127.0.0.1:${screenServer.address().port}`,
      amlServer, screenServer,
      close: async () => { await stop(screenServer); await stop(amlServer); } };
  } catch (error) {
    if (screenServer) await stop(screenServer);
    await stop(amlServer);
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 0 && (args.length !== 4 || args[0] !== "--intent" || args[2] !== "--context")) {
      throw new TypeError("use --intent path/to/intent.json --context path/to/context.json");
    }
    const scenario = args.length ? loadScenarioFiles(args[1], args[3]) : null;
    const port = Number(process.env.AML_SCREEN_PORT ?? "4173");
    const pilot = await startScreenPilot({ port, scenario });
    process.stdout.write(`Open ${pilot.url} in a browser. Press Ctrl+C to stop.\n`);
  } catch (error) {
    process.stderr.write(`Screen pilot failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
