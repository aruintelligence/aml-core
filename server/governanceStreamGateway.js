import http from "node:http";
import readline from "node:readline";
import {
  createGovernanceStreamSession,
  AML_GOVERNANCE_STREAM_OPEN,
  AML_GOVERNANCE_STREAM_ERROR
} from "../protocol/governanceStream.js";

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store"
  });
  res.end(payload);
}

function writeNdjson(res, value) {
  res.write(`${JSON.stringify(value)}\n`);
}

export function createGovernanceStreamGateway(options = {}) {
  const maxLineBytes = options.max_line_bytes ?? 256 * 1024;

  return http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", "http://localhost");

    if (req.method === "GET" && url.pathname === "/health") {
      return json(res, 200, {
        ok: true,
        service: "aml-governance-stream-gateway",
        protocol: "aml-governance-stream-http/1"
      });
    }

    if (req.method !== "POST" || url.pathname !== "/v1/governance/stream") {
      return json(res, 404, { error: "not_found" });
    }

    res.writeHead(200, {
      "content-type": "application/x-ndjson; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    });

    const rl = readline.createInterface({ input: req, crlfDelay: Infinity });
    let session = null;
    let lineNumber = 0;

    try {
      for await (const raw of rl) {
        lineNumber += 1;
        if (Buffer.byteLength(raw) > maxLineBytes) {
          throw new Error("governance stream line exceeds max_line_bytes");
        }
        const line = raw.trim();
        if (!line) continue;
        const message = JSON.parse(line);

        if (!session) {
          if (message.protocol !== AML_GOVERNANCE_STREAM_OPEN) {
            throw new Error("first NDJSON message must be aml-governance-stream-open/1");
          }
          session = createGovernanceStreamSession(message);
          writeNdjson(res, {
            protocol: AML_GOVERNANCE_STREAM_OPEN,
            accepted: true,
            transmission: session.transmission,
            profile: session.profile,
            mode: session.mode,
            failure_mode: session.failure_mode
          });
          continue;
        }

        writeNdjson(res, session.accept(message));
      }

      if (!session) throw new Error("governance stream contained no open message");
      if (!session.finalized) throw new Error("governance stream ended before aml-governance-stream-finalize/1");
      res.end();
    } catch (error) {
      writeNdjson(res, {
        protocol: AML_GOVERNANCE_STREAM_ERROR,
        line: lineNumber || null,
        error: error.message || String(error)
      });
      res.end();
    }
  });
}
