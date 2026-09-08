import http from "node:http";
import { executeAccountableIntent, verifyExecutionReceipt } from "../compiler/accountablePipeline.js";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";
import { verifyWitnessBundle } from "../docs/aml-witness-bundle.js";
import fs from "node:fs";

function send(res, status, body, headers = {}) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    ...headers
  });
  res.end(payload);
}

function readJson(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(Object.assign(new Error("request_too_large"), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(Object.assign(new Error("invalid_json"), { statusCode: 400 }));
      }
    });
    req.on("error", reject);
  });
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
  const defaultProfile = options.default_profile ?? "human_first";
  const allowedOrigin = options.allowed_origin ?? null;
  const trustRoots = options.brand_trust_roots ?? loadBrandTrustRoots();

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
        "access-control-allow-headers": "content-type"
      });
      return res.end();
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
