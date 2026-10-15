// Minimal host-side render gate for the locked reference HTTP service.
// The host owns the URL, bearer token, signer trust, expected policy, and renderer.
import { randomBytes } from "node:crypto";
import { verifySignedExecutionReceipt } from "../../compiler/accountablePipeline.js";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const blocked = (reason, receipt_sha256 = null) => ({
  status: "blocked", reason, render_attempted: false, receipt_sha256
});
const validTrustAnchors = values => Array.isArray(values) && values.length > 0 &&
  values.every(value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value));

export async function applyVerifiedDecision({ httpStatus, body, intent, profile, context,
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

export async function evaluateAndGate({ url, token, intent, profile, context, render,
  trustedReceiptFingerprints, fetchImpl = fetch }) {
  if (typeof render !== "function") throw new TypeError("host render callback required");
  if (!validTrustAnchors(trustedReceiptFingerprints)) return blocked("trust_anchor_unavailable");
  if (typeof token !== "string" || !token) return blocked("authentication_unavailable");
  const requestNonce = randomBytes(32).toString("hex");
  let response;
  let body;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ intent, request_nonce: requestNonce })
    });
    body = await response.json();
  } catch {
    return blocked("transport_or_response_error");
  }
  return applyVerifiedDecision({ httpStatus: response.status, body, intent, profile, context,
    trustedReceiptFingerprints, requestNonce, render });
}
