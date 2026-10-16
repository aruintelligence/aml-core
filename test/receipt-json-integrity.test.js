import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { executeAccountableIntent, replayExecutionReceipt, signExecutionReceipt,
  verifyExecutionReceipt, verifySignedExecutionReceipt } from "../index.js";

const intent = { transmission: "receipt_integrity", nodes: [
  { type: "message", properties: { content: "Safe message", attention_cost: 1,
    restoration_value: 3 } }
] };
const options = { timestamp: "2030-01-01T00:00:00.000Z" };
const { privateKey } = crypto.generateKeyPairSync("ed25519");
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

test("receipt issuance rejects non-JSON inputs that would disappear from a hash", () => {
  for (const value of [undefined, NaN, Infinity, new Date(options.timestamp), new Map()]) {
    assert.throws(() => executeAccountableIntent(intent, {
      ...options, context: { audit_note: value }
    }), /AML_CANONICAL_JSON_/);
  }
  const sparse = Array(1);
  const extra = ["first"];
  extra.audit_note = "not serialized";
  for (const history of [sparse, extra]) {
    assert.throws(() => executeAccountableIntent(intent, {
      ...options, context: { history }
    }), /AML_CANONICAL_JSON_NON_JSON_ARRAY/);
  }
  const getter = Object.defineProperty({}, "audit_note", {
    enumerable: true, get() { throw new Error("getter must not run"); }
  });
  const hidden = Object.defineProperty({}, "audit_note", { value: "omitted" });
  for (const context of [getter, hidden, { [Symbol("audit_note")]: "omitted" }]) {
    assert.throws(() => executeAccountableIntent(intent, { ...options, context }),
      /AML_CANONICAL_JSON_NON_JSON_OBJECT/);
  }
  assert.throws(() => executeAccountableIntent({ ...intent, audit_note: undefined }, options),
    /AML_CANONICAL_JSON_UNSUPPORTED_VALUE/);
  const omittedNonce = executeAccountableIntent(intent, { ...options, request_nonce: undefined });
  assert.equal(Object.hasOwn(omittedNonce, "request_nonce"), false);
  assert.equal(replayExecutionReceipt(omittedNonce).verified, true);
});

test("non-JSON mutations to a signed receipt fail integrity and signature checks", () => {
  const signed = signExecutionReceipt(executeAccountableIntent(intent, {
    ...options, context: { history: [] }
  }), privateKeyPem, { signer: "receipt-test", timestamp: options.timestamp });
  assert.equal(verifySignedExecutionReceipt(signed).verified, true);
  assert.equal(replayExecutionReceipt(JSON.parse(JSON.stringify(signed))).verified, true);

  for (const mutate of [
    receipt => { receipt.context.audit_note = undefined; },
    receipt => { receipt.context.history = Array(1); },
    receipt => { receipt.context.history.audit_note = "invisible"; },
    receipt => { Object.defineProperty(receipt.context, "hidden", { value: "invisible" }); }
  ]) {
    const changed = structuredClone(signed);
    mutate(changed);
    assert.equal(changed.receipt_sha256, signed.receipt_sha256);
    assert.equal(verifyExecutionReceipt(changed).canonical_json_valid, false);
    assert.equal(verifyExecutionReceipt(changed).verified, false);
    assert.equal(verifySignedExecutionReceipt(changed).verified, false);
    assert.equal(replayExecutionReceipt(changed).integrity_valid, false);
    assert.throws(() => signExecutionReceipt(changed, privateKeyPem), /invalid ĀML execution receipt/);
  }
});

test("signature verification rejects unsigned extension fields in an attestation", () => {
  const signed = signExecutionReceipt(executeAccountableIntent(intent, options), privateKeyPem);
  const changed = structuredClone(signed);
  changed.signature.audit_note = "unsigned assertion";
  assert.equal(verifyExecutionReceipt(changed).verified, true);
  assert.equal(verifySignedExecutionReceipt(changed).verified, false);
});
