// Durable single-use store (at-most-once consumption across processes).
//
// Each consumption is one file created with O_CREAT|O_EXCL ("wx"): the
// exclusive create is the single atomic commit point, so there is no window
// between "check" and "commit" for a second process to slip through. The file
// contents are written and fsync'd, then the directory is fsync'd, BEFORE the
// caller is told the consumption succeeded; the caller executes only after
// that. Consequences:
//   - replay after a process restart or from another process sharing the
//     directory is refused (the file exists);
//   - a crash after the exclusive create but before the record is complete
//     leaves a present-but-partial file, which still counts as consumed
//     (fail closed: the authorization is burned, the action may not have run);
//   - a crash before the create leaves nothing; the action never ran.
// This is at-most-once, never at-least-once. Established technique (lock /
// maildir style exclusive create + fsync). Requires a local POSIX filesystem
// with atomic O_EXCL (not NFSv2 / some network filesystems).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createExclusiveDurable } from "./trustConfig.js";

export const DURABLE_CONSUMPTION_STORE_TYPE = "aml-durable-consumption-store/1";
const HEX64 = /^[a-f0-9]{64}$/;
// Only stores opened by this module count; a look-alike object never does.
const OPENED = new WeakSet();

export function consumptionKey(parts) {
  if (!Array.isArray(parts) || parts.length === 0 || !parts.every(p => typeof p === "string" && p.length > 0 && !p.includes("\u0000"))) {
    throw new Error("AML_CONSUMPTION_KEY_INVALID");
  }
  return crypto.createHash("sha256").update(`aml-consumption/1\u0000${parts.join("\u0000")}`).digest("hex");
}

export function openDurableConsumptionStore(dir) {
  if (typeof dir !== "string" || dir.length === 0) throw new Error("AML_CONSUMPTION_STORE_DIR_REQUIRED");
  const root = path.resolve(dir);
  fs.mkdirSync(path.join(root, "consumed"), { recursive: true, mode: 0o700 });
  const fileFor = key => {
    if (typeof key !== "string" || !HEX64.test(key)) throw new Error("AML_CONSUMPTION_KEY_INVALID");
    return path.join(root, "consumed", `${key}.json`);
  };
  const store = Object.freeze({
    type: DURABLE_CONSUMPTION_STORE_TYPE,
    dir: root,
    // Returns true exactly once per key across all processes sharing `dir`.
    // Throws on I/O errors; callers must treat a throw as "not consumed by
    // me" and deny.
    consume(key, record = {}) {
      const body = `${JSON.stringify({ ...record, type: "aml-consumption-record/1", key, consumed_at: new Date().toISOString(), pid: process.pid })}\n`;
      return createExclusiveDurable(fileFor(key), body);
    },
    // Diagnostic only; never use has() followed by an action (that is the
    // check-then-act race consume() exists to avoid).
    has(key) { return fs.existsSync(fileFor(key)); }
  });
  OPENED.add(store);
  return store;
}

export function isDurableConsumptionStore(store) {
  return Boolean(store) && typeof store === "object" && OPENED.has(store);
}
