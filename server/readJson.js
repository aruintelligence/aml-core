// Bounded JSON intake for the reference HTTP service. The caller closes the
// connection after a 413 so a rejected upload cannot occupy a keep-alive slot.
import { TextDecoder } from "node:util";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";

export function readJson(req, maxBytes = 1024 * 1024) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new TypeError("maxBytes must be a positive safe integer");
  }

  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const chunks = [];

    const cleanup = (keepError = false) => {
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

    // An early rejection avoids buffering an advertised oversized body. Never
    // destroy the request here: doing so can reset the socket before the 413.
    const length = req.headers["content-length"];
    if (typeof length === "string" && /^\d+$/.test(length) && BigInt(length) > BigInt(maxBytes)) {
      fail("request_too_large", 413, true);
    }
  });
}
