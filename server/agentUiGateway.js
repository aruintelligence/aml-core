import http from "node:http";
import { evaluateAgentUI, AML_AGENT_UI_ENVELOPE, AML_AGENT_UI_RESULT } from "../adapters/agent-ui.js";

function send(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store"
  });
  res.end(payload);
}

function readJson(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", chunk => {
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

export function createAgentUiGateway(options = {}) {
  const maxBodyBytes = options.max_body_bytes ?? 1024 * 1024;
  const defaultProfile = options.default_profile ?? "calm_default";
  const defaultMode = options.default_mode ?? "enforce";
  const defaultFailureMode = options.default_failure_mode ?? "closed";

  return http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", "http://localhost");

    if (req.method === "GET" && url.pathname === "/health") {
      return send(res, 200, {
        ok: true,
        service: "aml-agent-ui-gateway",
        protocol: "aml-agent-ui-gateway/1",
        accepts: AML_AGENT_UI_ENVELOPE,
        returns: AML_AGENT_UI_RESULT
      });
    }

    if (req.method === "POST" && url.pathname === "/v1/agent-ui/evaluate") {
      try {
        const body = await readJson(req, maxBodyBytes);
        const envelope = body.envelope ?? body;
        const result = evaluateAgentUI(envelope, {
          profile: body.profile ?? defaultProfile,
          mode: body.mode ?? defaultMode,
          failure_mode: body.failure_mode ?? defaultFailureMode,
          context: body.context ?? {},
          timestamp: body.timestamp
        });
        return send(res, result.errors > 0 ? 422 : 200, result);
      } catch (error) {
        return send(res, error.statusCode ?? 400, {
          protocol: "aml-agent-ui-gateway-error/1",
          error: error.message || "agent_ui_evaluation_failed"
        });
      }
    }

    return send(res, 404, { error: "not_found" });
  });
}
