// Host-side gate for nonce-bound signed responses from the locked HTTP service.
// The host owns its token, signer trust, expected inputs, and render callback.
import { randomBytes } from "node:crypto";
import { verifySignedExecutionReceipt } from "../compiler/accountablePipeline.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

const blocked = (reason, receipt_sha256 = null) => ({
  status: "blocked", reason, render_attempted: false, receipt_sha256
});
const validTrustAnchors = values => Array.isArray(values) && values.length > 0 &&
  values.every(value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value));

export async function applyLockedHttpDecision({ httpStatus, body, intent, profile, context,
  trustedReceiptFingerprints, requestNonce, render }) {
  if (typeof render !== "function") throw new TypeError("host render callback required");
  if (!validTrustAnchors(trustedReceiptFingerprints)) {
    return blocked("trust_anchor_unavailable");
  }
  if (typeof requestNonce !== "string" || !/^[0-9a-f]{64}$/.test(requestNonce)) {
    return blocked("request_nonce_missing");
  }
  if (httpStatus !== 200) return blocked("http_evaluation_unavailable");
  if (body?.protocol !== "aml-http-deployment-evaluation/1" || body.policy_source !== "server" ||
      body.mode !== "enforce" || body.failure_mode !== "closed" || body.evaluation_error !== null) {
    return blocked("unexpected_deployment_policy");
  }

  const receipt = body.receipt;
  try {
    const signature = verifySignedExecutionReceipt(receipt);
    if (!signature.verified || !signature.attribution_bound || receipt.signature.version !== "1.1") {
      return blocked("receipt_invalid");
    }
    if (!trustedReceiptFingerprints.includes(receipt.signature.public_key_sha256)) {
      return blocked("receipt_untrusted");
    }
    if (receipt.profile?.id !== profile ||
        receipt.request_nonce !== requestNonce ||
        canonicalJSONStringify(receipt.intent) !== canonicalJSONStringify(intent) ||
        canonicalJSONStringify(receipt.context) !== canonicalJSONStringify(context)) {
      return blocked("receipt_binding_mismatch", receipt.receipt_sha256);
    }
    const allowed = receipt.selected_render.suppressed === 0;
    if (body.aml_allowed !== allowed || body.effective_allowed !== allowed ||
        body.would_suppress !== !allowed) {
      return blocked("decision_mismatch", receipt.receipt_sha256);
    }
    if (!allowed) return blocked("policy_suppressed", receipt.receipt_sha256);
  } catch {
    return blocked("receipt_invalid");
  }

  try {
    await render(receipt.selected_render.html);
    return { status: "rendered", reason: "verified_allow", render_attempted: true,
      receipt_sha256: receipt.receipt_sha256 };
  } catch {
    // A callback may change the UI before it throws. Do not claim no render.
    return { status: "unknown", reason: "render_callback_error", render_attempted: true,
      receipt_sha256: receipt.receipt_sha256 };
  }
}

function responseTooLarge() {
  return Object.assign(new Error("HTTP evaluation response too large"), { code: "AML_RESPONSE_TOO_LARGE" });
}

async function readBoundedJson(response, maxResponseBytes) {
  const advertised = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(advertised) && advertised > maxResponseBytes) throw responseTooLarge();
  if (typeof response.body?.getReader !== "function") {
    throw new TypeError("streaming response body required");
  }
  const reader = response.body.getReader();
  const parts = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError("invalid response chunk");
      bytes += value.byteLength;
      if (bytes > maxResponseBytes) throw responseTooLarge();
      parts.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true })
    .decode(Buffer.concat(parts, bytes)));
}

export async function evaluateLockedHttpAndRender({ url, token, intent, profile, context, render,
  trustedReceiptFingerprints, timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, fetchImpl = fetch }) {
  if (typeof render !== "function") throw new TypeError("host render callback required");
  if (!validTrustAnchors(trustedReceiptFingerprints)) return blocked("trust_anchor_unavailable");
  if (typeof token !== "string" || !token) return blocked("authentication_unavailable");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError("timeoutMs must be a positive safe integer");
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) {
    throw new TypeError("maxResponseBytes must be a positive safe integer");
  }
  if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
  // Preserve the trust inputs and the exact JSON intent sent over the wire.
  // A mutable caller object cannot change what a later response is checked against.
  const trustedPins = [...trustedReceiptFingerprints];
  let expectedContext;
  let expectedIntent;
  let requestBody;
  const requestNonce = randomBytes(32).toString("hex");
  try {
    expectedContext = JSON.parse(canonicalJSONStringify(context));
    requestBody = JSON.stringify({ intent, request_nonce: requestNonce });
    expectedIntent = JSON.parse(requestBody).intent;
    if (expectedIntent == null) return blocked("invalid_host_input");
  } catch {
    return blocked("invalid_host_input");
  }
  const controller = new AbortController();
  let timer;
  let outcome;
  try {
    outcome = await Promise.race([
      (async () => {
        const response = await fetchImpl(url, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
          body: requestBody,
          signal: controller.signal
        });
        if (response.status !== 200) return { httpStatus: response.status, body: null };
        return { httpStatus: response.status, body: await readBoundedJson(response, maxResponseBytes) };
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(Object.assign(new Error("HTTP evaluation timed out"), { code: "AML_EVALUATION_TIMEOUT" }));
        }, timeoutMs);
      })
    ]);
  } catch (error) {
    controller.abort();
    if (error?.code === "AML_EVALUATION_TIMEOUT") return blocked("evaluation_timeout");
    if (error?.code === "AML_RESPONSE_TOO_LARGE") return blocked("response_too_large");
    return blocked("transport_or_response_error");
  } finally {
    clearTimeout(timer);
  }
  if (outcome.httpStatus !== 200) controller.abort();
  return applyLockedHttpDecision({ ...outcome, intent: expectedIntent, profile,
    context: expectedContext, trustedReceiptFingerprints: trustedPins, requestNonce, render });
}
