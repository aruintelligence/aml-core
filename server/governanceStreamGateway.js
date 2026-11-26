import http from "node:http";
import { randomUUID } from "node:crypto";
import { createRequestAuthenticator } from "./requestAuth.js";
import { createInflightLimit } from "./inflightLimit.js";
import { createLockedHttpPolicy } from "./lockedPolicy.js";
import { readNdjsonLines } from "./readNdjsonLines.js";
import { writeNdjson } from "./writeNdjson.js";
import {
  createGovernanceStreamSession,
  AML_GOVERNANCE_STREAM_OPEN,
  AML_GOVERNANCE_STREAM_POLICY_UPDATE,
  AML_GOVERNANCE_STREAM_ERROR
} from "../protocol/governanceStream.js";

const STREAM_CONTROLS = ["profile", "mode", "failure_mode", "context", "timestamp", "stream_id", "stream_ids"];
const hasOwn = (value, key) => value !== null && typeof value === "object" && Object.hasOwn(value, key);

function json(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    ...headers,
    ...([400, 401, 413, 503].includes(status) ? { connection: "close" } : {})
  });
  res.end(payload);
}

// Finite public protocol surface: values, never arbitrary error details, leave
// the process. Matching an input string is NOT authentication or authorization.
const publicProtocolErrors = new Map([
  ...[
    ["unauthorized", 401], ["authentication_unavailable", 503],
    ["policy_override_forbidden", 403], ["trusted_context_unavailable", 503],
    ["invalid_request_body", 400], ["invalid_json", 400],
    ["governance stream exceeds max_stream_bytes", 413],
    ["governance stream line exceeds max_line_bytes", 413],
    ["governance stream exceeds max_messages", 413],
    ["first NDJSON message must be aml-governance-stream-open/1", 400],
    ["governance stream contained no open message", 400],
    ["governance stream ended before aml-governance-stream-finalize/1", 400],
    ["profile must be a non-empty string", 400], ["mode must be enforce or shadow", 400],
    ["failure_mode must be closed or open", 400], ["policy context must be an object.", 400],
    ["open must be an object.", 400], ["open.policy_authorization must be an object.", 400],
    ["stream node must be an object.", 400], ["stream node.type is required.", 400],
    ["AML_STREAM_ALREADY_FINALIZED", 400], ["AML_GOVERNANCE_STREAM_ALREADY_FINALIZED", 400],
    ["AML_POLICY_TRANSITION_AUTHORIZATION_REQUIRED", 400],
    ["AML_POLICY_TRANSITION_AUTHORIZATION_MISMATCH", 400]
  ].map(([message, status]) => [message, Object.freeze({ error: message, status })])
]);
const publicProtocolPrefixes = [
  ["AML_STREAM_DUPLICATE_IDENTIFIER:", "AML_STREAM_DUPLICATE_IDENTIFIER"],
  ["AML_POLICY_TRANSITION_UNAUTHORIZED:", "AML_POLICY_TRANSITION_UNAUTHORIZED"],
  ["Unsupported governance stream protocol:", "unsupported_governance_stream_protocol"],
  ["Unsupported governance stream message protocol:", "unsupported_governance_stream_message"]
];
function publicFailure(error, authentication = false) {
  let message;
  try { message = error?.message; } catch { /* no arbitrary getter output */ }
  const known = typeof message === "string" ? publicProtocolErrors.get(message) : undefined;
  if (authentication) return known && ["unauthorized", "authentication_unavailable"].includes(known.error)
    ? known : { status: 503, error: "authentication_unavailable" };
  if (known) return known;
  if (typeof message === "string") {
    for (const [prefix, code] of publicProtocolPrefixes) {
      if (message.startsWith(prefix)) return { status: 400, error: code };
    }
  }
  return { status: 400, error: "governance_stream_failed" };
}
function responseClosed(error) {
  try { return error?.code === "AML_RESPONSE_CLOSED"; } catch { return false; }
}

export function createGovernanceStreamGateway(options = {}) {
  const maxLineBytes = options.max_line_bytes ?? 256 * 1024;
  const maxStreamBytes = options.max_stream_bytes ?? 8 * 1024 * 1024;
  const maxMessages = options.max_messages ?? 1000;
  if (!Number.isSafeInteger(maxLineBytes) || maxLineBytes < 1) {
    throw new TypeError("max_line_bytes must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maxStreamBytes) || maxStreamBytes < 1) {
    throw new TypeError("max_stream_bytes must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maxMessages) || maxMessages < 2) {
    throw new TypeError("max_messages must be a safe integer of at least 2");
  }
  const authorize = createRequestAuthenticator(options.request_auth, { timeout_ms: options.auth_timeout_ms });
  const inflight = createInflightLimit(options.max_inflight_requests);
  const bearerChallenge = options.request_auth && typeof options.request_auth === "object"
    ? { "www-authenticate": 'Bearer realm="aml"' } : {};
  const lockedPolicy = createLockedHttpPolicy(options.locked_policy, "calm_default");

  return http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", "http://localhost");

    if (req.method === "GET" && url.pathname === "/health") {
      return json(res, 200, {
        ok: true,
        service: "aml-governance-stream-gateway",
        protocol: "aml-governance-stream-http/1"
      });
    }

    if (req.method === "POST" && !inflight.acquire(res)) {
      req.pause();
      return json(res, 503, { error: "server_busy" }, { "retry-after": "1" });
    }

    if (authorize && req.method === "POST") {
      try {
        await authorize(req);
      } catch (error) {
        const failure = publicFailure(error, true);
        return json(res, failure.status, { error: failure.error },
          failure.status === 401 ? bearerChallenge : {});
      }
    }

    if (req.method !== "POST" || url.pathname !== "/v1/governance/stream") {
      return json(res, 404, { error: "not_found" });
    }

    const length = req.headers["content-length"];
    if (typeof length === "string" && /^\d+$/.test(length) && BigInt(length) > BigInt(maxStreamBytes)) {
      return json(res, 413, { error: "governance stream exceeds max_stream_bytes" });
    }

    let session = null;
    let lineNumber = 0;
    let messageCount = 0;

    try {
      for await (const raw of readNdjsonLines(req, {
        max_line_bytes: maxLineBytes,
        max_stream_bytes: maxStreamBytes
      })) {
        lineNumber += 1;
        const line = raw.trim();
        if (!line) continue;
        messageCount += 1;
        if (messageCount > maxMessages) {
          throw Object.assign(new Error("governance stream exceeds max_messages"), { statusCode: 413 });
        }
        let message;
        try { message = JSON.parse(line); }
        catch { throw new Error("invalid_json"); }

        if (!session) {
          if (message.protocol !== AML_GOVERNANCE_STREAM_OPEN) {
            throw new Error("first NDJSON message must be aml-governance-stream-open/1");
          }
          if (lockedPolicy && hasOwn(message, "policy_authorization")) {
            throw new Error("policy_override_forbidden");
          }
          const controls = lockedPolicy ? await lockedPolicy.select(message, req) : null;
          session = createGovernanceStreamSession(controls ? {
            ...message,
            profile: controls.profile,
            mode: controls.mode,
            failure_mode: controls.failure_mode,
            context: controls.context,
            timestamp: controls.timestamp
          } : message, lockedPolicy ? { stream_id_factory: randomUUID } : {});
          res.writeHead(200, {
            "content-type": "application/x-ndjson; charset=utf-8",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff"
          });
          await writeNdjson(res, {
            protocol: AML_GOVERNANCE_STREAM_OPEN,
            accepted: true,
            transmission: session.transmission,
            profile: session.profile,
            mode: session.mode,
            failure_mode: session.failure_mode,
            ...(lockedPolicy ? { policy_source: "server" } : {})
          });
          continue;
        }

        if (lockedPolicy && (message?.protocol === AML_GOVERNANCE_STREAM_POLICY_UPDATE ||
            STREAM_CONTROLS.some(key => hasOwn(message, key)))) {
          throw new Error("policy_override_forbidden");
        }
        await writeNdjson(res, session.accept(message));
      }

      if (!session) throw new Error("governance stream contained no open message");
      if (!session.finalized) throw new Error("governance stream ended before aml-governance-stream-finalize/1");
      res.end();
    } catch (error) {
      if (res.destroyed || res.writableEnded || responseClosed(error)) return;
      const publicError = publicFailure(error);
      const failure = {
        protocol: AML_GOVERNANCE_STREAM_ERROR,
        line: lineNumber || null,
        error: publicError.error
      };
      if (!res.headersSent) return json(res, publicError.status, failure);
      try {
        await writeNdjson(res, failure);
        res.end();
      } catch {
        res.destroy();
      }
    }
  });
}
