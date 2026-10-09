import http from "node:http";
import { readJson } from "./readJson.js";
import { createLockedHttpPolicy } from "./lockedPolicy.js";
import { createRequestAuthenticator } from "./requestAuth.js";
import { executeAccountableIntent, verifyExecutionReceipt } from "../compiler/accountablePipeline.js";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";
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
    ...([401, 413, 503].includes(status) ? { connection: "close" } : {})
  });
  res.end(payload);
}

function loadJson(relativePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(new URL(relativePath, import.meta.url), "utf8"));
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

export function createAmlHttpServer(options = {}) {
  const maxBodyBytes = options.max_body_bytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
    throw new TypeError("max_body_bytes must be a positive safe integer");
  }
  const defaultProfile = options.default_profile ?? "human_first";
  const allowedOrigin = options.allowed_origin ?? null;
  const trustRoots = options.brand_trust_roots ?? loadBrandTrustRoots();
  const lockedPolicy = createLockedHttpPolicy(options.locked_policy, defaultProfile);
  const maxBatchItems = options.max_batch_items ?? 100;
  if (!Number.isSafeInteger(maxBatchItems) || maxBatchItems < 1) {
    throw new TypeError("max_batch_items must be a positive safe integer");
  }
  const authorize = createRequestAuthenticator(options.request_auth);
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
        const body = await readJson(req, maxBodyBytes);
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
        const body = await readJson(req, maxBodyBytes);
        if (!body.intent) return send(res, 400, { error: "intent_required" }, headers);
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
          stream_id: body.stream_id,
        });
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
        const body = await readJson(req, maxBodyBytes);
        if (!Array.isArray(body.intents)) return send(res, 400, { error: "intents_array_required" }, headers);
        if (!lockedPolicy && body.intents.length > maxBatchItems) {
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
          ...controls
        });
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
        const body = await readJson(req, maxBodyBytes);
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
        const body = await readJson(req, maxBodyBytes);
        if (!body.receipt) return send(res, 400, { error: "receipt_required" }, headers);
        const verification = verifyExecutionReceipt(body.receipt);
        return send(res, verification.verified ? 200 : 422, verification, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "verification_failed" }, headers);
      }
    }

    if (req.method === "POST" && url.pathname === "/v1/verify-witness-bundle") {
      try {
        const body = await readJson(req, maxBodyBytes);
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
        const body = await readJson(req, maxBodyBytes);
        if (!body.credential) return send(res, 400, { error: "credential_required" }, headers);
        const result = verifyOfficialBrandAuthorization(body.credential, trustRoots, {
          now: body.now ?? null,
          revocation_registry: body.revocation_registry ?? null,
          expected_issuer: trustRoots.owner ?? "ĀRU Intelligence Inc."
        });
        return send(res, result.valid && result.official ? 200 : 422, result, headers);
      } catch (error) {
        return send(res, error.statusCode ?? 400, { error: error.message || "brand_verification_failed" }, headers);
      }
    }

    return send(res, 404, { error: "not_found" }, headers);
  });
}
