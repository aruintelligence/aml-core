import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDurableCapabilityAuthorizer,
  openDurableConsumptionStore,
  signCapabilityToken
} from "../../index.js";

const sha256 = value => createHash("sha256").update(value).digest("hex");
const dir = mkdtempSync(join(tmpdir(), "aml-payment-request-"));
try {
  const ledger = join(dir, "requests.jsonl");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const issuerKey = privateKey.export({ type: "pkcs8", format: "pem" });
  const audience = "local-payment-request-ledger";
  const subject = "sandbox-agent";
  const sessionId = randomUUID();
  const requiredCapability = "payment-request:record";
  const request = { operation_id: randomUUID(), amount_minor: 12500, currency: "USD" };
  const requestBytes = JSON.stringify(request);
  const configureHost = () => createDurableCapabilityAuthorizer({
    trustedIssuerKeySha256: sha256(publicKey.export({ type: "spki", format: "der" })),
    audience,
    consumptionStore: openDurableConsumptionStore(join(dir, "authority"))
  });
  const now = Date.now();
  const issue = expiresAt => signCapabilityToken({
    issuer: "sandbox-approver",
    subject,
    audience,
    capabilities: [requiredCapability],
    session_id: sessionId,
    intent_sha256: sha256(requestBytes),
    nonce: randomUUID(),
    issued_at: new Date(now - 60_000).toISOString(),
    expires_at: new Date(expiresAt).toISOString()
  }, issuerKey);
  const token = issue(now + 60_000);

  function submit(authorize, permit, exactBytes) {
    const decision = authorize(permit, {
      subject, sessionId, requiredCapability, intentSha256: sha256(exactBytes)
    });
    if (decision.authorized === true) appendFileSync(ledger, exactBytes + "\n");
    return decision;
  }

  const authorize = configureHost();
  const outcomes = {
    unauthorized: submit(authorize, null, requestBytes),
    expired: submit(authorize, issue(now - 1000), requestBytes),
    changed: submit(authorize, token, JSON.stringify({ ...request, amount_minor: 13000 })),
    approved: submit(authorize, token, requestBytes),
    replayAfterReopen: submit(configureHost(), token, requestBytes)
  };
  assert.equal(outcomes.approved.authorized, true);
  assert.equal(outcomes.approved.replay_protection, "durable");
  for (const name of ["unauthorized", "expired", "changed", "replayAfterReopen"]) {
    assert.equal(outcomes[name].authorized, false, name);
  }
  assert.equal(readFileSync(ledger, "utf8"), requestBytes + "\n");
  console.log(JSON.stringify({
    sandbox: true,
    decisions: Object.fromEntries(Object.entries(outcomes).map(([name, decision]) => [
      name, { authorized: decision.authorized, reasons: decision.reasons, replay_protection: decision.replay_protection }
    ])),
    recorded_payment_requests: 1
  }, null, 2));
} finally {
  rmSync(dir, { recursive: true, force: true });
}
