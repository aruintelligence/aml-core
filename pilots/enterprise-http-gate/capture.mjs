// Save real loopback HTTP evaluations for verification without the JS gate.
// Only synthetic repository fixtures are used. The private key and token stay in memory.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { createAmlHttpServer, createEvidenceCapsule, executeAccountableIntent,
  replayExecutionReceipt, resolvePolicyProfile, signExecutionReceipt,
  verifySignedExecutionReceipt } from "../../index.js";

if (process.argv.length !== 4 || process.argv[2] !== "--out") {
  throw new TypeError("usage: node pilots/enterprise-http-gate/capture.mjs --out <new-directory>");
}
const directory = path.resolve(process.argv[3]);
const fixture = name => JSON.parse(fs.readFileSync(new URL(`../enterprise-30min/${name}`, import.meta.url), "utf8"));
const context = fixture("context-denied.json");
const profile = "human_first";
const token = randomBytes(32).toString("hex");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const fingerprint = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
const server = createAmlHttpServer({ request_auth: { bearer_token: token },
  locked_policy: { profile, context, mode: "enforce", failure_mode: "closed" },
  receipt_signing: { private_key_pem: privateKeyPem, signer: "localhost-capture" } });
const save = (name, value) => fs.writeFileSync(path.join(directory, name), `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" });
const sha256 = value => createHash("sha256").update(value).digest("hex");
const sortedJson = value => Array.isArray(value) ? `[${value.map(sortedJson).join(",")}]` :
  value && typeof value === "object" ? `{${Object.keys(value).sort()
    .map(key => `${JSON.stringify(key)}:${sortedJson(value[key])}`).join(",")}}` : JSON.stringify(value);
const receiptHash = value => sha256(typeof value === "string" ? value : sortedJson(value));

fs.mkdirSync(directory);
try {
  // A host pins this independently of the response; the fixture capture generates
  // both sides in one process and is not evidence of organizational identity.
  save("trusted-policy.json", { trusted_receipt_fingerprints: [fingerprint] });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}/v1/deployment/evaluate`;
  const results = [];
  const baseline = {};
  for (const [name, intentName, shouldAllow] of [
    ["allow", "intent-allowed.json", true], ["suppress", "intent-sensitive.json", false],
    ["numeric", "intent-allowed.json", true], ["keys", "intent-allowed.json", true],
    ["large", "intent-allowed.json", true]
  ]) {
    const intent = fixture(intentName);
    if (name === "numeric") intent.numeric_probe = 1e-7;
    if (name === "large") {
      intent.numeric_probe = 2 ** 53;
      intent.large_exponent_probe = 1e100;
    }
    if (name === "keys") intent.key_probe = {
      "10": "ten", "2": "two", "\uE000": "private use", "\u{1F4A1}": "astral", lone: "\uD800"
    };
    const request_nonce = randomBytes(32).toString("hex");
    const expected = { protocol: "aml-locked-http-host-expected/2", intent, profile,
      profile_snapshot: resolvePolicyProfile(profile), context, request_nonce };
    save(`host-expected-${name}.json`, expected);
    const response = await fetch(url, { method: "POST", headers: {
      "content-type": "application/json", authorization: `Bearer ${token}`
    }, body: JSON.stringify({ intent, request_nonce }) });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.receipt?.request_nonce, request_nonce);
    assert.equal(body.effective_allowed, shouldAllow);
    save(`exchange-${name}.json`, { protocol: "aml-locked-http-exchange/1", http_status: response.status, body });
    save(`capsule-${name}.json`, createEvidenceCapsule(body.receipt));
    if (name === "allow" || name === "suppress") baseline[name] = { body, expected };
    results.push({ id: name, receipt_sha256: body.receipt.receipt_sha256,
      output_sha256: body.receipt.output_sha256 });
  }
  // Deliberately sign two false claims with the trusted fixture key. A
  // signature proves key possession, not that the compiler produced the data.
  const fabricated = structuredClone(baseline.allow.body);
  const inventedHtml = "<h2>Signed output the engine never generated</h2>";
  const altered = fabricated.receipt;
  altered.selected_render.html = inventedHtml;
  altered.output_sha256 = receiptHash(inventedHtml);
  const event = altered.runtime_audit_stream.entries.at(-1);
  event.payload.output_sha256 = altered.output_sha256;
  const { entry_hash, ...eventCore } = event;
  event.entry_hash = receiptHash(eventCore);
  altered.audit_stream_sha256 = receiptHash(altered.runtime_audit_stream);
  const { signature, receipt_sha256, ...payload } = altered;
  altered.receipt_sha256 = receiptHash(payload);
  fabricated.receipt = signExecutionReceipt(altered, privateKeyPem, { signer: "localhost-capture" });
  assert.equal(verifySignedExecutionReceipt(fabricated.receipt).verified, true);
  assert.equal(replayExecutionReceipt(fabricated.receipt).verified, false);
  save("host-expected-forged-output.json", baseline.allow.expected);
  save("exchange-forged-output.json", { protocol: "aml-locked-http-exchange/1", http_status: 200, body: fabricated });
  save("capsule-forged-output.json", createEvidenceCapsule(fabricated.receipt));
  results.push({ id: "forged-output", receipt_sha256: fabricated.receipt.receipt_sha256,
    output_sha256: fabricated.receipt.output_sha256 });

  const weakened = structuredClone(baseline.suppress.body);
  const suppressedReceipt = baseline.suppress.body.receipt;
  const weakReceipt = executeAccountableIntent(baseline.suppress.expected.intent, {
    profile: { id: profile, description: "Same ID, fewer policies.", policies: ["restorative_v1"] },
    context, request_nonce: baseline.suppress.expected.request_nonce,
    timestamp: suppressedReceipt.timestamp, stream_id: suppressedReceipt.runtime_audit_stream.stream_id
  });
  assert.equal(weakReceipt.selected_render.suppressed, 0);
  weakened.receipt = signExecutionReceipt(weakReceipt, privateKeyPem, { signer: "localhost-capture" });
  assert.equal(replayExecutionReceipt(weakened.receipt).verified, true);
  weakened.selected_render = weakReceipt.selected_render;
  weakened.aml_allowed = true;
  weakened.effective_allowed = true;
  weakened.would_suppress = false;
  save("host-expected-weaker-profile.json", baseline.suppress.expected);
  save("exchange-weaker-profile.json", { protocol: "aml-locked-http-exchange/1", http_status: 200, body: weakened });
  save("capsule-weaker-profile.json", createEvidenceCapsule(weakened.receipt));
  results.push({ id: "weaker-profile", receipt_sha256: weakened.receipt.receipt_sha256,
    output_sha256: weakened.receipt.output_sha256 });
  process.stdout.write(`${JSON.stringify({ protocol: "aml-locked-http-capture/2", cases: results,
    claim_boundary: "Synthetic project fixtures over loopback; saved parsed HTTP JSON and host inputs, no external witness or production identity." }, null, 2)}\n`);
} finally {
  if (server.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
