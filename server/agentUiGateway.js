import http from "node:http";
import { evaluateAgentUI, AML_AGENT_UI_ENVELOPE, AML_AGENT_UI_RESULT } from "../adapters/agent-ui.js";
import { readJson } from "./readJson.js";
import { createRequestAuthenticator } from "./requestAuth.js";

function send(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    ...([401, 413, 503].includes(status) ? { connection: "close" } : {})
  });
  res.end(payload);
}

export function createAgentUiGateway(options = {}) {
  const maxBodyBytes = options.max_body_bytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
    throw new TypeError("max_body_bytes must be a positive safe integer");
  }
  const defaultProfile = options.default_profile ?? "calm_default";
  const defaultMode = options.default_mode ?? "enforce";
  const defaultFailureMode = options.default_failure_mode ?? "closed";
  const authorize = createRequestAuthenticator(options.request_auth);

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

    if (authorize && req.method === "POST") {
      try {
        await authorize(req);
      } catch (error) {
        return send(res, error.statusCode ?? 503, {
          protocol: "aml-agent-ui-gateway-error/1",
          error: error.message
        });
      }
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
