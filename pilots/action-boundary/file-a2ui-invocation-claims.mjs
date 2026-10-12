// Host-owned, local-filesystem A2UI invocation claims shared by Node workers.
// Keep the directory private and durable for the entire host session lifetime.
// This is not a network filesystem or multi-machine store.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const text = value => typeof value === "string" && value.trim().length > 0 &&
  value.length <= 256;

export function createFileA2UIInvocationClaims({ directory, sessionFor } = {}) {
  if (typeof directory !== "string" || !path.isAbsolute(directory) ||
      typeof sessionFor !== "function") {
    throw new TypeError("A trusted absolute directory and host session resolver are required");
  }

  // Provision the directory separately. Silently creating it after a restart
  // could forget a whole session's spent IDs and let old messages replay.
  function privateDirectory() {
    const info = fs.lstatSync(directory);
    if (!info.isDirectory() || (info.mode & 0o077) !== 0 ||
        typeof process.getuid !== "function" || info.uid !== process.getuid()) {
      throw new Error("private_invocation_directory_required");
    }
    return info;
  }
  const original = privateDirectory();

  function claim({ functionCallId } = {}, context) {
    const sessionId = sessionFor(context);
    if (!text(sessionId) || !text(functionCallId)) {
      throw new TypeError("A trusted host session and A2UI functionCallId are required");
    }
    const info = privateDirectory();
    if (info.dev !== original.dev || info.ino !== original.ino) {
      throw new Error("invocation_directory_replaced");
    }
    const key = JSON.stringify([sessionId, functionCallId]);
    const file = path.join(directory, `${crypto.createHash("sha256").update(key).digest("hex")}.claim`);
    let fd;
    try { fd = fs.openSync(file, "wx", 0o600); }
    catch (error) {
      if (error.code === "EEXIST") return false;
      throw error;
    }
    // The exclusive create is the local linearization point. Any later write
    // or sync failure leaves the marker spent and propagates to the gate,
    // which refuses to call the tool.
    try {
      fs.writeFileSync(fd, JSON.stringify({ protocol: "aml-a2ui-invocation-claim/1",
        key_sha256: path.basename(file, ".claim") }) + "\n");
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    const dirFd = fs.openSync(directory, "r");
    try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
    return true;
  }

  return { claim };
}
