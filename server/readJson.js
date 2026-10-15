// Bounded JSON intake for the reference HTTP service. The caller closes the
// connection after a 408 or 413 so an unfinished upload cannot keep a slot.
import { TextDecoder } from "node:util";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";

export function readJson(req, maxBytes = 1024 * 1024, timeoutMs = 10_000) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new TypeError("maxBytes must be a positive safe integer");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) {
    throw new TypeError("timeoutMs must be a positive integer within the timer range");
  }

  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    let timer;
    const chunks = [];

    const cleanup = (keepError = false) => {
      clearTimeout(timer);
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("aborted", onAborted);
      if (keepError) req.once("close", () => req.off("error", onError));
      else req.off("error", onError);
    };
    const fail = (message, statusCode, pause = false) => {
      if (settled) return;
      settled = true;
      cleanup(pause);
      if (pause) req.pause();
      reject(Object.assign(new Error(message), { statusCode }));
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > maxBytes) return fail("request_too_large", 413, true);
      chunks.push(chunk);
    };
    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      try {
        // Preserve JSON.parse's BOM behavior while refusing lossy UTF-8
        // replacement and duplicate keys at every nesting level.
        const raw = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
          .decode(Buffer.concat(chunks));
        resolve(raw ? parseJsonWithoutDuplicateKeys(raw) : {});
      } catch (error) {
        const reason = error?.code === "AML_DUPLICATE_JSON_KEY" ? "ambiguous_json" : "invalid_json";
        reject(Object.assign(new Error(reason), { statusCode: 400 }));
      }
    };
    const onError = (error) => fail(error.message || "request_error", 400);
    const onAborted = () => fail("request_aborted", 400);

    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("aborted", onAborted);
    // An absolute deadline bounds a client that sends a byte and then stalls.
    timer = setTimeout(() => fail("request_timeout", 408, true), timeoutMs);

    // An early rejection avoids buffering an advertised oversized body. Never
    // destroy the request here: doing so can reset the socket before the reply.
    const length = req.headers["content-length"];
    if (typeof length === "string" && /^\d+$/.test(length) && BigInt(length) > BigInt(maxBytes)) {
      fail("request_too_large", 413, true);
    }
  });
}
