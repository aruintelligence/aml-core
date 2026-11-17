// Cooperative local-writer serialization, NOT an adversarial administrator lock.
import fs from "node:fs";
import path from "node:path";

export function appendOnlyFile(file, expected) {
  if (typeof expected !== "string" || Buffer.byteLength(expected) > 64 * 1024 * 1024) throw new TypeError("invalid_append_only_bytes");
  if (typeof fs.constants.O_NOFOLLOW !== "number") throw new Error("append_only_nofollow_unsupported");
  const lock = file + ".write-lock";
  fs.mkdirSync(lock, { mode: 0o700 }); // Existing/orphan locks reject; never remove someone else's lock.
  let fd;
  try {
    const flags = fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW | (fs.constants.O_NONBLOCK ?? 0);
    try { fd = fs.openSync(file, flags); }
    catch (error) {
      if (error.code !== "ENOENT") throw error;
      fd = fs.openSync(file, flags | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
    }
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1 || info.size > 64 * 1024 * 1024) throw new Error("append_only_regular_file_required");
    // A same-inode writer can grow after fstat: never perform an unbounded read.
    const retainedBytes = Buffer.alloc(info.size + 1); let retainedLength = 0;
    while (retainedLength < retainedBytes.length) {
      const n = fs.readSync(fd, retainedBytes, retainedLength, retainedBytes.length - retainedLength, retainedLength);
      if (!n) break;
      retainedLength += n;
    }
    if (retainedLength !== info.size || fs.fstatSync(fd).size !== info.size) throw new Error("append_only_concurrent_change");
    const retained = retainedBytes.subarray(0, retainedLength).toString("utf8");
    if (!expected.startsWith(retained)) throw new Error("existing registry rows are immutable; new receipts must append");
    const delta = Buffer.from(expected.slice(retained.length)); let written = 0;
    while (written < delta.length) {
      const n = fs.writeSync(fd, delta, written, delta.length - written);
      if (n <= 0) throw new Error("append_only_write_incomplete");
      written += n;
    }
    fs.fsyncSync(fd);
    // A non-cooperating append must not be silently overwritten or reported valid.
    // It can still race AFTER this check; administrator/parent manipulation is excluded.
    const size = fs.fstatSync(fd).size;
    if (size !== Buffer.byteLength(expected)) throw new Error("append_only_concurrent_change");
    const bytes = Buffer.alloc(size); let offset = 0;
    while (offset < size) { const n = fs.readSync(fd, bytes, offset, size - offset, offset); if (!n) break; offset += n; }
    if (offset !== size || bytes.toString("utf8") !== expected) throw new Error("append_only_concurrent_change");
    const directory = fs.openSync(path.dirname(file), "r");
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmdirSync(lock);
  }
}
