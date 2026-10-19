import http from "node:http";
import { createPrivateKey, randomUUID } from "node:crypto";
import { readJson } from "./readJson.js";
import { createLockedHttpPolicy } from "./lockedPolicy.js";
import { createRequestAuthenticator } from "./requestAuth.js";
import { createInflightLimit } from "./inflightLimit.js";
import { executeAccountableIntent, signExecutionReceipt, verifyExecutionReceipt } from "../compiler/accountablePipeline.js";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";
import { createDeploymentFirewall } from "../runtime/deploymentFirewall.js";
import { evaluateInterfaceBatch } from "../runtime/batchInterfaceFirewall.js";
import { evaluatePolicyCanary } from "../runtime/policyCanary.js";
import { verifyWitnessBundle } from "../docs/aml-witness-bundle.js";
import fs from "node:fs";

function send(res, status, body, headers = {}) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    ...headers,
    ...([401, 408, 413, 503].includes(status) ? { connection: "close" } : {})
  });
  res.end(payload);
}

function loadJson(relativePath, fallback) {
  try {
    const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
      .decode(fs.readFileSync(new URL(relativePath, import.meta.url)));
    return parseJsonWithoutDuplicateKeys(source);
  } catch {
    return fallback;
  }
}

function loadCapabilities() {
  return loadJson("../AML_CAPABILITIES.json", { language: "ĀML — ĀRU Meaning Language", status: "capabilities_unavailable" });
}

function loadBrandTrustRoots() {
  return loadJson("../BRAND_TRUST_ROOTS.json", {
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    status: "unavailable",
    active_keys: [],
    revoked_keys: []
  });
}

const REQUEST_NONCE = /^[0-9a-f]{64}$/;

function createReceiptSigner(config, lockedPolicy) {
  if (config == null) return null;
  if (!lockedPolicy) throw new TypeError("receipt_signing requires locked_policy");
  if (typeof config !== "object" || Array.isArray(config) ||
      Object.keys(config).some(key => key !== "private_key_pem" && key !== "signer") ||
      typeof config.private_key_pem !== "string" ||
      typeof config.signer !== "string" || !config.signer.trim()) {
    throw new TypeError("receipt_signing requires private_key_pem and a nonempty signer");
  }
  const privateKeyPem = config.private_key_pem;
  const signer = config.signer;
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new TypeError("receipt_signing key must be Ed25519");
  return receipt => signExecutionReceipt(receipt, privateKeyPem, { signer });
}

function signDeploymentReceipt(deployment, signer) {
  const receipt = deployment.result?.receipt;
  if (!receipt) return;
  const signed = signer(receipt);
  deployment.result.receipt = signed;
  if (deployment.result.report) deployment.result.report.receipt = signed;
}

export function createAmlHttpServer(options = {}) {
  const maxBodyBytes = options.max_body_bytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
    throw new TypeError("max_body_bytes must be a positive safe integer");
  }
  const bodyTimeoutMs = options.request_body_timeout_ms ?? 10_000;
  if (!Number.isSafeInteger(bodyTimeoutMs) || bodyTimeoutMs < 1 || bodyTimeoutMs > 2_147_483_647) {
    throw new TypeError("request_body_timeout_ms must be a positive integer within the timer range");
  }
  const defaultProfile = options.default_profile ?? "human_first";
  const allowedOrigin = options.allowed_origin ?? null;
  const trustRoots = options.brand_trust_roots ?? loadBrandTrustRoots();
  const brandRevocationRegistry = options.brand_revocation_registry ?? null;
  const lockedPolicy = createLockedHttpPolicy(options.locked_policy, defaultProfile);
  const receiptSigner = createReceiptSigner(options.receipt_signing, lockedPolicy);
  const maxBatchItems = options.max_batch_items ?? 100;
  if (!Number.isSafeInteger(maxBatchItems) || maxBatchItems < 1) {
    throw new TypeError("max_batch_items must be a positive safe integer");
  }
  const authorize = createRequestAuthenticator(options.request_auth, { timeout_ms: options.auth_timeout_ms });
  const inflight = createInflightLimit(options.max_inflight_requests);
  const bearerChallenge = options.request_auth && typeof options.request_auth === "object"
    ? { "www-authenticate": 'Bearer realm="aml"' } : {};

  return http.createServer(async (req, res) => {
    const headers = allowedOrigin ? { "access-control-allow-origin": allowedOrigin } : {};
    const url = new URL(req.url || "/", "http://localhost");

    if (req.method === "GET" && url.pathname === "/health") {
      return send(res, 200, { ok: true, service: "aml-http", protocol: "aml-http/1" }, headers);
    }

    if (req.method === "GET" && url.pathname === "/v1/capabilities") {
      return send(res, 200, loadCapabilities(), headers);
    }

    if (req.method === "GET" && url.pathname === "/v1/brand-trust-roots") {
      return send(res, 200, trustRoots, headers);
    }

    if (req.method === "OPTIONS" && allowedOrigin) {
      res.writeHead(204, {
        ...headers,
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": authorize ? "content-type, authorization" : "content-type"
      });
      return res.end();
    }

    if (req.method === "POST" && !inflight.acquire(res)) {
      req.pause();
      return send(res, 503, { error: "server_busy" }, { ...headers, "retry-after": "1" });
    }

    if (authorize && req.method === "POST") {
      try {
        await authorize(req);
      } catch (error) {
        return send(res, error.statusCode ?? 503, { error: error.message }, {
          ...headers,
          ...(error.statusCode === 401 ? bearerChallenge : {})
        });
      }
    }

    if (lockedPolicy && req.method === "POST" &&
      (url.pathname === "/v1/evaluate" || url.pathname === "/v1/deployment/canary")) {
      return send(res, 403, { error: "endpoint_disabled_under_locked_policy" }, headers);
    }

    if (req.method === "POST" && url.pathname === "/v1/evaluate") {
      try {
        const body = await readJson(req, maxBodyBytes, bodyTimeoutMs);
        if (!body.intent) return send(res, 400, { error: "intent_required" }, headers);
        const receipt = executeAccountableIntent(body.intent, {
          profile: body.profile ?? defaultProfile,
          context: body.context ?? {},
          timestamp: body.timestamp,
          stream_id: body.stream_id
        });
        return send(res, 200, {
          protocol: "aml-http-evaluation/1",
          allowed: receipt.selected_render.suppressed === 0,
          selected_render: receipt.selected_render,
          receipt
        }, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "evaluation_failed" }, headers);
      }
    }

    if (req.method === "POST" && url.pathname === "/v1/deployment/evaluate") {
      try {
        const body = await readJson(req, maxBodyBytes, bodyTimeoutMs);
        if (!body.intent) return send(res, 400, { error: "intent_required" }, headers);
        if (receiptSigner && !REQUEST_NONCE.test(body.request_nonce)) {
          return send(res, 400, { error: "invalid_request_nonce" }, headers);
        }
        const controls = lockedPolicy ? await lockedPolicy.select(body, req) : {
          profile: body.profile ?? defaultProfile,
          context: body.context ?? {},
          mode: body.mode ?? "enforce",
          failure_mode: body.failure_mode ?? "closed",
          timestamp: body.timestamp
        };
        const firewall = createDeploymentFirewall(controls);
        const result = firewall.evaluate(body.intent, {
          ...controls,
          // The audit stream identifies this server evaluation. A locked
          // caller must not choose or reuse another evaluation's stream ID.
          stream_id: lockedPolicy ? randomUUID() : body.stream_id,
          ...(receiptSigner ? { request_nonce: body.request_nonce } : {}),
        });
        if (receiptSigner) {
          try { signDeploymentReceipt(result, receiptSigner); }
          catch { return send(res, 503, { error: "receipt_signing_unavailable" }, headers); }
        }
        return send(res, result.evaluation_error ? 422 : 200, {
          protocol: "aml-http-deployment-evaluation/1",
          policy_source: lockedPolicy ? "server" : "request_or_default",
          mode: result.mode,
          failure_mode: result.failure_mode,
          aml_allowed: result.aml_allowed,
          effective_allowed: result.effective_allowed,
          would_suppress: result.would_suppress,
          evaluation_error: result.evaluation_error,
          selected_render: result.result?.receipt?.selected_render ?? null,
          receipt: result.result?.receipt ?? null
        }, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "deployment_evaluation_failed" }, headers);
      }
    }

    if (req.method === "POST" && url.pathname === "/v1/deployment/batch") {
      try {
        const body = await readJson(req, maxBodyBytes, bodyTimeoutMs);
        if (!Array.isArray(body.intents)) return send(res, 400, { error: "intents_array_required" }, headers);
        if (receiptSigner && !REQUEST_NONCE.test(body.request_nonce)) {
          return send(res, 400, { error: "invalid_request_nonce" }, headers);
        }
        // Reject excess work before resolving trusted context or allocating
        // audit IDs. The configured locked ceiling is independent of the
        // unlocked server ceiling.
        if (body.intents.length > (lockedPolicy ? lockedPolicy.max_batch_items : maxBatchItems)) {
          return send(res, 413, { error: "batch_limit_exceeded" }, headers);
        }
        const controls = lockedPolicy ? await lockedPolicy.select(body, req) : {
          profile: body.profile ?? defaultProfile,
          context: body.context ?? {},
          mode: body.mode ?? "enforce",
          failure_mode: body.failure_mode ?? "closed",
          timestamp: body.timestamp,
          max_items: body.max_items ?? maxBatchItems
        };
        const result = evaluateInterfaceBatch(body.intents, {
          ...controls,
          // Each locked item is a separate server evaluation, even when the
          // intent and request-wide timestamp are identical.
          ...(lockedPolicy ? { stream_ids: body.intents.map(() => randomUUID()) } : {}),
          ...(receiptSigner ? { request_nonce: body.request_nonce } : {})
        });
        if (receiptSigner) {
          try { result.results.forEach(item => signDeploymentReceipt(item.evaluation, receiptSigner)); }
          catch { return send(res, 503, { error: "receipt_signing_unavailable" }, headers); }
        }
        return send(res, 200, {
          ...result,
          protocol: "aml-http-deployment-batch/1",
          policy_source: lockedPolicy ? "server" : "request_or_default",
          runtime_protocol: result.protocol
        }, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "deployment_batch_failed" }, headers);
      }
    }

    if (req.method === "POST" && url.pathname === "/v1/deployment/canary") {
      try {
        const body = await readJson(req, maxBodyBytes, bodyTimeoutMs);
        if (!body.intent) return send(res, 400, { error: "intent_required" }, headers);
        const result = evaluatePolicyCanary(body.intent, {
          baseline_profile: body.baseline_profile ?? "calm_default",
          candidate_profile: body.candidate_profile ?? defaultProfile,
          context: body.context ?? {},
          timestamp: body.timestamp
        });
        return send(res, 200, {
          ...result,
          protocol: "aml-http-policy-canary/1",
          runtime_protocol: result.protocol
        }, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "policy_canary_failed" }, headers);
      }
    }

    if (req.method === "POST" && url.pathname === "/v1/verify-receipt") {
      try {
        const body = await readJson(req, maxBodyBytes, bodyTimeoutMs);
        if (!body.receipt) return send(res, 400, { error: "receipt_required" }, headers);
        const verification = verifyExecutionReceipt(body.receipt);
        return send(res, verification.verified ? 200 : 422, verification, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "verification_failed" }, headers);
      }
    }

    if (req.method === "POST" && url.pathname === "/v1/verify-witness-bundle") {
      try {
        const body = await readJson(req, maxBodyBytes, bodyTimeoutMs);
        if (!body.bundle) return send(res, 400, { error: "bundle_required" }, headers);
        const now = body.now == null
          ? Date.now()
          : (typeof body.now === "number" ? body.now : Date.parse(body.now));
        if (!Number.isFinite(now)) return send(res, 400, { error: "invalid_now" }, headers);
        const result = await verifyWitnessBundle(body.bundle, { now });
        return send(res, result.valid ? 200 : 422, {
          protocol: "aml-http-witness-verification/1",
          ...result
        }, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "witness_verification_failed" }, headers);
      }
    }

    if (req.method === "POST" && url.pathname === "/v1/verify-brand-authorization") {
      try {
        const body = await readJson(req, maxBodyBytes, bodyTimeoutMs);
        if (!body.credential) return send(res, 400, { error: "credential_required" }, headers);
        if (Object.hasOwn(body, "now")) return send(res, 400, { error: "caller_time_not_allowed" }, headers);
        if (Object.hasOwn(body, "revocation_registry")) return send(res, 400, { error: "caller_revocation_registry_not_allowed" }, headers);
        const result = verifyOfficialBrandAuthorization(body.credential, trustRoots, {
          revocation_registry: brandRevocationRegistry
        });
        return send(res, result.valid && result.official ? 200 : 422, result, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "brand_verification_failed" }, headers);
      }
    }

    return send(res, 404, { error: "not_found" }, headers);
  });
}
