import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomUUID, verify } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createDurableCapabilityAuthorizer, openDurableConsumptionStore, signCapabilityToken
} from "../../index.js";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const destinationScript = fileURLToPath(new URL("./payment-request-destination.py", import.meta.url));
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const dir = mkdtempSync(join(tmpdir(), "aml-destination-"));
try {
  const issuer = generateKeyPairSync("ed25519");
  const destination = generateKeyPairSync("ed25519");
  const destinationKey = join(dir, "destination.pem");
  writeFileSync(destinationKey, destination.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const database = join(dir, "ledger.sqlite");
  const audience = "sandbox-payment-ledger";
  const subject = "sandbox-agent";
  const sessionId = randomUUID();
  const requiredCapability = "payment-request:record";
  const operation_id = randomUUID();
  const request = JSON.stringify({ operation_id, amount_minor: 12500, currency: "USD" });
  const intentSha256 = sha256(request);
  const authorize = createDurableCapabilityAuthorizer({
    trustedIssuerKeySha256: sha256(issuer.publicKey.export({ type: "spki", format: "der" })),
    audience,
    consumptionStore: openDurableConsumptionStore(join(dir, "authority"))
  });
  const issue = (digest = intentSha256) => signCapabilityToken({
    issuer: "sandbox-approver", audience, subject, session_id: sessionId,
    capabilities: [requiredCapability], nonce: randomUUID(), intent_sha256: digest,
    expires_at: new Date(Date.now() + 60_000).toISOString()
  }, issuer.privateKey.export({ type: "pkcs8", format: "pem" }));
  const bindings = { subject, sessionId, requiredCapability, intentSha256 };
  const permit = issue();
  assert.equal(authorize(permit, bindings).authorized, true);

  function stopDuringSubmit(bytes, point) {
    const delivery = spawnSync("python3", [destinationScript, "submit", database, point], {
      input: bytes, encoding: "utf8", timeout: 10_000
    });
    assert.ifError(delivery.error);
    assert.equal(delivery.status, null, delivery.stderr);
    assert.equal(delivery.signal, "SIGKILL", delivery.stderr);
    assert.equal(delivery.stdout, "");
  }

  stopDuringSubmit(request, "after-commit");
  assert.equal(authorize(permit, bindings).authorized, false);

  function readStatus(operationId) {
    const result = spawnSync("python3", [destinationScript, "status", database, operationId, destinationKey], {
      encoding: "utf8", timeout: 10_000
    });
    assert.equal(result.status, 0, result.stderr ?? String(result.error));
    return JSON.parse(result.stdout);
  }

  function recover() {
    const { statement, signature_hex } = readStatus(operation_id);
    assert.deepEqual(statement, {
      profile: "aml-sandbox-payment-status/1", destination: audience, operation_id,
      request_sha256: intentSha256, outcome: "recorded"
    });
    assert.match(signature_hex, /^[a-f0-9]{128}$/);
    const signedBytes = Buffer.from(canonicalJSONStringify(statement));
    const signature = Buffer.from(signature_hex, "hex");
    assert.equal(verify(null, signedBytes, destination.publicKey, signature), true);
    assert.equal(verify(null, signedBytes, issuer.publicKey, signature), false);
    return { statement, signature_hex };
  }

  const receipt = recover();
  // A distinct valid permit can reauthorize the same business operation.
  // The destination, which owns the operation ID, retains the original row.
  assert.equal(authorize(issue(), bindings).authorized, true);
  const repeat = spawnSync("python3", [destinationScript, "submit", database], {
    input: request, encoding: "utf8", timeout: 10_000
  });
  assert.equal(repeat.status, 0, repeat.stderr ?? String(repeat.error));
  assert.deepEqual(recover(), receipt);
  const interruptedId = randomUUID();
  const interruptedRequest = JSON.stringify({ operation_id: interruptedId, amount_minor: 2200, currency: "USD" });
  const interruptedDigest = sha256(interruptedRequest);
  const interruptedPermit = issue(interruptedDigest);
  const interruptedBindings = { ...bindings, intentSha256: interruptedDigest };
  assert.equal(authorize(interruptedPermit, interruptedBindings).authorized, true);
  stopDuringSubmit(interruptedRequest, "before-commit");
  assert.equal(readStatus(interruptedId), null);
  assert.equal(authorize(interruptedPermit, interruptedBindings).authorized, false);
  assert.deepEqual(recover(), receipt);

  console.log(JSON.stringify({
    sandbox: true, acknowledgment: "none", permit_replay: "denied",
    before_commit: { signal: "SIGKILL", outcome: "unresolved", receipt: null },
    after_commit: { signal: "SIGKILL", outcome: "recorded" },
    outcome: "verified with pinned destination public key", receipt
  }, null, 2));
} finally {
  rmSync(dir, { recursive: true, force: true });
}
