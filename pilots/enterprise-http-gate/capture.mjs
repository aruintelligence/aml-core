// Save real loopback HTTP evaluations for verification without the JS gate.
// Only synthetic repository fixtures are used. The private key and token stay in memory.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { createAmlHttpServer, createEvidenceCapsule } from "../../index.js";

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
const server = createAmlHttpServer({ request_auth: { bearer_token: token },
  locked_policy: { profile, context, mode: "enforce", failure_mode: "closed" },
  receipt_signing: { private_key_pem: privateKey.export({ type: "pkcs8", format: "pem" }), signer: "localhost-capture" } });
const save = (name, value) => fs.writeFileSync(path.join(directory, name), `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" });

fs.mkdirSync(directory);
try {
  // A host pins this independently of the response; the fixture capture generates
  // both sides in one process and is not evidence of organizational identity.
  save("trusted-policy.json", { trusted_receipt_fingerprints: [fingerprint] });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}/v1/deployment/evaluate`;
  const results = [];
  for (const [name, intentName, shouldAllow] of [
    ["allow", "intent-allowed.json", true], ["suppress", "intent-sensitive.json", false],
    ["numeric", "intent-allowed.json", true]
  ]) {
    const intent = fixture(intentName);
    if (name === "numeric") intent.numeric_probe = 1e-7;
    const request_nonce = randomBytes(32).toString("hex");
    const expected = { protocol: "aml-locked-http-host-expected/1", intent, profile, context, request_nonce };
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
    results.push({ id: name, receipt_sha256: body.receipt.receipt_sha256,
      output_sha256: body.receipt.output_sha256 });
  }
  process.stdout.write(`${JSON.stringify({ protocol: "aml-locked-http-capture/1", cases: results,
    claim_boundary: "Synthetic project fixtures over loopback; saved parsed HTTP JSON and host inputs, no external witness or production identity." }, null, 2)}\n`);
} finally {
  if (server.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
