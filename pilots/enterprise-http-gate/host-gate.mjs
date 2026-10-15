// Minimal host-side render gate for the locked reference HTTP service.
// The host owns the URL, bearer token, expected policy, and render callback.
import { verifyExecutionReceipt } from "../../compiler/accountablePipeline.js";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const blocked = (reason, receipt_sha256 = null) => ({
  status: "blocked", reason, render_attempted: false, receipt_sha256
});

export async function applyVerifiedDecision({ httpStatus, body, intent, profile, context, render }) {
  if (typeof render !== "function") throw new TypeError("host render callback required");
  if (httpStatus !== 200) return blocked("http_evaluation_unavailable");
  if (body?.protocol !== "aml-http-deployment-evaluation/1" || body.policy_source !== "server" ||
      body.mode !== "enforce" || body.failure_mode !== "closed" || body.evaluation_error !== null) {
    return blocked("unexpected_deployment_policy");
  }

  const receipt = body.receipt;
  try {
    if (!verifyExecutionReceipt(receipt).verified) return blocked("receipt_invalid");
    if (receipt.profile?.id !== profile ||
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
  fetchImpl = fetch }) {
  if (typeof render !== "function") throw new TypeError("host render callback required");
  let response;
  let body;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ intent })
    });
    body = await response.json();
  } catch {
    return blocked("transport_or_response_error");
  }
  return applyVerifiedDecision({ httpStatus: response.status, body, intent, profile, context, render });
}
