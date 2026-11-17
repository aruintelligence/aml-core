import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { decodeSignatureBase64 } from "../protocol/strictBase64.js";
import { trustConfigTrustsKey, trustConfigRequiresSingleUse } from "./trustConfig.js";
import { consumptionKey, isDurableConsumptionStore } from "./consumptionStore.js";

function fingerprint(publicKey) {
  return crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

function validTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validateTimes({ issued_at = null, expires_at = null } = {}) {
  if (issued_at !== null && !validTimestamp(issued_at)) return "invalid_issued_at";
  if (expires_at !== null && !validTimestamp(expires_at)) return "invalid_expires_at";
  if (issued_at !== null && expires_at !== null && Date.parse(expires_at) <= Date.parse(issued_at)) {
    return "invalid_time_window";
  }
  return null;
}

export function signCapabilityToken({ issuer, subject = null, audience = null, capabilities = [], issued_at = null, expires_at = null, nonce = null, session_id = null, intent_sha256 = null } = {}, privateKeyPem) {
  if (!issuer) throw new Error("issuer is required");
  if (!privateKeyPem) throw new Error("private key is required");
  const timeError = validateTimes({ issued_at, expires_at });
  if (timeError) throw new Error(timeError);

  const body = {
    type: "aml-capability-token/1",
    issuer,
    subject,
    audience,
    capabilities: [...new Set(capabilities)].sort(),
    issued_at,
    expires_at,
    nonce,
    // Optional bindings (Directive 010). Omitted when null so tokens signed
    // without them keep byte-identical canonical bodies and signatures.
    ...(session_id === null ? {} : { session_id }),
    ...(intent_sha256 === null ? {} : { intent_sha256 })
  };

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const message = Buffer.from(canonicalJSONStringify(body));

  return {
    ...body,
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    public_key_fingerprint: fingerprint(publicKey),
    signature_base64: crypto.sign(null, message, privateKey).toString("base64")
  };
}

export function verifyCapabilityToken(token, { now = null, audience = null, requiredCapability = null } = {}) {
  if (!token || token.type !== "aml-capability-token/1") return { valid: false, reason: "invalid_type" };
  const { public_key_pem, public_key_fingerprint, signature_base64, ...body } = token;

  try {
    const publicKey = crypto.createPublicKey(public_key_pem);
    if (fingerprint(publicKey) !== public_key_fingerprint) return { valid: false, reason: "fingerprint_mismatch" };
    const signature = decodeSignatureBase64(signature_base64);
    if (signature === null) return { valid: false, reason: "signature_invalid" };
    const signatureValid = crypto.verify(null, Buffer.from(canonicalJSONStringify(body)), publicKey, signature);
    if (!signatureValid) return { valid: false, reason: "signature_invalid" };
  } catch {
    return { valid: false, reason: "signature_invalid" };
  }

  const timeError = validateTimes(token);
  if (timeError) return { valid: false, reason: timeError };
  if (now !== null && !validTimestamp(now)) return { valid: false, reason: "invalid_now" };
  if (now && token.expires_at && Date.parse(now) >= Date.parse(token.expires_at)) return { valid: false, reason: "expired" };
  if (audience && token.audience !== audience) return { valid: false, reason: "audience_mismatch" };
  if (requiredCapability && !token.capabilities.includes(requiredCapability)) return { valid: false, reason: "capability_missing" };

  return { valid: true, reason: null, issuer: token.issuer, subject: token.subject, capabilities: token.capabilities };
}

// Directive 010: `valid` above only means "well-formed and signed by the key
// embedded in the token" - any party can mint such a token for any
// capability. authorizeCapabilityToken is the only function in this module
// whose result may gate an action. It is authorized only when every check
// below is explicitly true:
//   - signature valid (verifyCapabilityToken) and issuer key fingerprint
//     equals a relying-party pin (signature validity != trusted identity);
//   - expiry evaluated against the verifier's local clock only - a caller
//     supplied time is never accepted (no `now` option exists);
//   - audience, subject (executor), session_id and intent_sha256 each equal
//     the value the relying party expects (evidence from another session,
//     executor or intent does not transfer);
//   - the required capability is granted;
//   - the (issuer key, nonce) pair has not been consumed in the supplied
//     replay guard; on success the returned guard records it, so a second
//     execution with the same token is refused.
// Residual: a stolen pinned issuer key still mints authorizing tokens, and
// the replay guard is only as durable as the caller's storage of it.
//
// Trust config + durable store (opt-in, additive; never weakens a pin):
//   - `trustConfig`: a decision from evaluateTrustConfig(All). When supplied,
//     the issuer key must be trusted for role "capability-issuer", not
//     revoked, and the config unexpired. If a hex pin is ALSO supplied, both
//     must hold. A stolen key is then stopped by publishing a config version
//     that revokes it (bounded by the config expiry for stale relying parties).
//   - `consumptionStore`: a store from openDurableConsumptionStore(). The
//     (issuer key, nonce) pair is consumed with an atomic exclusive create
//     after every other check passed, so replay across process restarts and
//     across executors sharing the store is refused. A trust config with
//     require_single_use: true makes the durable store mandatory.
const PIN = /^[0-9a-f]{64}$/;
export function createCapabilityConsumptionGuard() {
  return { type: "aml-capability-consumption/1", consumed: {} };
}

export function authorizeCapabilityToken(token, {
  trustedIssuerKeySha256 = null,
  audience = null,
  subject = null,
  sessionId = null,
  intentSha256 = null,
  requiredCapability = null,
  consumptionGuard = null,
  trustConfig = null,
  consumptionStore = null
} = {}) {
  const reasons = [];
  const verification = verifyCapabilityToken(token, { audience: null, requiredCapability: null });
  const nowMs = Date.now();
  const checks = {
    signature_valid: verification.valid === true,
    issuer_key_pinned: verification.valid === true && (trustedIssuerKeySha256 !== null || trustConfig !== null)
      && (trustedIssuerKeySha256 === null || (typeof trustedIssuerKeySha256 === "string" && PIN.test(trustedIssuerKeySha256)
        && token.public_key_fingerprint === trustedIssuerKeySha256))
      && (trustConfig === null || trustConfigTrustsKey(trustConfig, token.public_key_fingerprint, "capability-issuer")),
    local_clock_trusted: Number.isFinite(nowMs),
    not_expired: false,
    audience_bound: typeof audience === "string" && audience.length > 0 && token?.audience === audience,
    executor_bound: typeof subject === "string" && subject.length > 0 && token?.subject === subject,
    session_bound: typeof sessionId === "string" && sessionId.length > 0 && token?.session_id === sessionId,
    intent_bound: typeof intentSha256 === "string" && PIN.test(intentSha256) && token?.intent_sha256 === intentSha256,
    capability_granted: typeof requiredCapability === "string" && Array.isArray(token?.capabilities)
      && token.capabilities.includes(requiredCapability),
    nonce_present: typeof token?.nonce === "string" && token.nonce.length > 0,
    not_replayed: false
  };
  if (checks.local_clock_trusted && validTimestamp(token?.expires_at)) {
    const issuedOk = token.issued_at === null || token.issued_at === undefined
      || (validTimestamp(token.issued_at) && Date.parse(token.issued_at) <= nowMs);
    checks.not_expired = issuedOk && nowMs < Date.parse(token.expires_at);
  }
  const guardOk = consumptionGuard?.type === "aml-capability-consumption/1" && consumptionGuard.consumed
    && typeof consumptionGuard.consumed === "object";
  const consumeKey = `${token?.public_key_fingerprint}:${token?.nonce}`;
  const guardFresh = Boolean(guardOk && checks.nonce_present && !Object.hasOwn(consumptionGuard.consumed, consumeKey));
  const durableRequired = trustConfig !== null && trustConfigRequiresSingleUse(trustConfig);
  let replayProtection = "none";
  if (consumptionStore !== null) {
    // Consume last, and only when everything else already passed, so a
    // denied attempt never burns a token. A supplied guard must also agree.
    const othersOk = Object.entries(checks).every(([name, ok]) => name === "not_replayed" || ok === true);
    checks.not_replayed = false;
    if (isDurableConsumptionStore(consumptionStore) && othersOk && (consumptionGuard === null || guardFresh)) {
      try {
        checks.not_replayed = consumptionStore.consume(
          consumptionKey(["capability-token", String(token.public_key_fingerprint), String(token.nonce)]),
          { purpose: "capability-token", issuer_key_sha256: token.public_key_fingerprint, executor: subject,
            session_id: sessionId, intent_sha256: intentSha256, audience, capability: requiredCapability,
            token_expires_at: token.expires_at }) === true;
        replayProtection = "durable";
      } catch {
        checks.not_replayed = false;
      }
    }
  } else {
    checks.not_replayed = guardFresh && !durableRequired;
    replayProtection = guardFresh ? "in-memory" : "none";
  }
  for (const [name, ok] of Object.entries(checks)) if (ok !== true) reasons.push(name);
  const authorized = reasons.length === 0;
  return {
    valid: checks.signature_valid,
    authorized,
    reasons,
    checks,
    replay_protection: authorized ? replayProtection : "none",
    consumptionGuard: authorized && guardOk
      ? { type: consumptionGuard.type, consumed: { ...consumptionGuard.consumed, [consumeKey]: new Date(nowMs).toISOString() } }
      : consumptionGuard
  };
}
