#!/usr/bin/env node
// Isolated fixture provider. The only side effect is an exclusive local marker.
import { open, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

const [mode, directory, operationId, requestDigest, requestBytes] = process.argv.slice(2);
if (!["ack", "lost_ack", "before_write", "reconcile"].includes(mode) ||
    !path.isAbsolute(directory) || !/^[a-f0-9-]{36}$/.test(operationId) ||
    !/^[a-f0-9]{64}$/.test(requestDigest)) throw new Error("Invalid fixture invocation");
if (mode !== "reconcile" &&
    (createHash("sha256").update(requestBytes || "").digest("hex") !== requestDigest ||
      JSON.parse(requestBytes).operation_id !== operationId)) {
  throw new Error("Provider request bytes do not match operation binding");
}
const file = path.join(directory, `${operationId}.json`);
if (mode === "reconcile") {
  let record = null;
  try { record = JSON.parse(await readFile(file, "utf8")); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  console.log(JSON.stringify({ record }));
} else if (mode === "before_write") {
  process.exitCode = 76; // Request was initiated; provider did not record it.
} else {
  const record = { protocol: "aml-local-provider-effect/1", operation_id: operationId,
    request_sha256: requestDigest, provider_status: "recorded",
    request: JSON.parse(requestBytes) };
  const handle = await open(file, "wx", 0o600);
  try { await handle.writeFile(JSON.stringify(record) + "\n"); await handle.sync(); }
  finally { await handle.close(); }
  const directoryHandle = await open(directory, "r");
  try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  if (mode === "lost_ack") process.exitCode = 75; // Effect exists; response lost.
  else console.log(JSON.stringify(record));
}
