#!/usr/bin/env node
// Standalone verifier for one fixture provider statement, not an AVEP verifier.
import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const DIGEST = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const exact = (value, fields) => value && typeof value === "object" &&
  !Array.isArray(value) && Object.keys(value).sort().join("|") === fields.sort().join("|");

export function verifyProviderStatus(envelope, { publicKey, operationId, requestSha256,
  destination, challenge } = {}) {
  try {
    const version = challenge === undefined ? 1 : 2;
    if (!exact(envelope, ["protocol", "issuer", "operation_id", "record", "signature",
      ...(version === 2 ? ["challenge"] : [])]) ||
        envelope.protocol !== `aml-fixture-provider-status/${version}` ||
        (version === 2 && (!DIGEST.test(challenge) || envelope.challenge !== challenge)) ||
        envelope.issuer !== "fixture-provider" || !ID.test(envelope.operation_id) ||
        envelope.operation_id !== operationId || !DIGEST.test(requestSha256) ||
        typeof destination !== "string" || !destination ||
        typeof envelope.signature !== "string" ||
        !/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature)) return "REJECTED";
    const statement = { protocol: envelope.protocol, issuer: envelope.issuer,
      operation_id: envelope.operation_id,
      ...(version === 2 ? { challenge: envelope.challenge } : {}), record: envelope.record };
    const bytes = Buffer.concat([Buffer.from(`AML-LOCAL-PROVIDER-STATUS/${version}\0`, "utf8"),
      Buffer.from(canonicalJSONStringify(statement), "utf8")]);
    const key = crypto.createPublicKey(publicKey);
    if (key.asymmetricKeyType !== "ed25519" ||
        !crypto.verify(null, bytes, key, Buffer.from(envelope.signature, "base64"))) {
      return "REJECTED";
    }
    if (envelope.record === null) return "INCOMPLETE";
    const record = envelope.record;
    if (!exact(record, ["operation_id", "request_sha256", "destination", "effect_id"]) ||
        record.operation_id !== operationId || record.request_sha256 !== requestSha256 ||
        record.destination !== destination || !ID.test(record.effect_id)) return "REJECTED";
    return "PROVIDER_REPORTED";
  } catch { return "REJECTED"; }
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const [publicKeyFile, operationId, requestSha256, destination, challenge] = process.argv.slice(2);
  try {
    const raw = fs.readFileSync(0, "utf8");
    if (Buffer.byteLength(raw, "utf8") > 8192) throw Error("oversized_provider_status");
    const envelope = JSON.parse(raw);
    // Exact canonical wire bytes exclude duplicate keys and alternate parser
    // interpretations before any signature or claim is evaluated.
    if (raw !== canonicalJSONStringify(envelope)) throw Error("noncanonical_provider_status");
    const result = verifyProviderStatus(envelope, { publicKey: fs.readFileSync(publicKeyFile),
      operationId, requestSha256, destination, challenge });
    console.log(JSON.stringify({ protocol: "aml-fixture-provider-verification/1", result,
      independent_confirmation: false }));
    if (result === "REJECTED") process.exitCode = 2;
  } catch {
    console.log(JSON.stringify({ protocol: "aml-fixture-provider-verification/1",
      result: "REJECTED", independent_confirmation: false }));
    process.exitCode = 2;
  }
}
