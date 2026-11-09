// Descriptor-based bounded read. This is not a hostile-owner/parent-directory boundary.
import fs from "node:fs";

export function readRegularFile(file, { maxBytes, privateOwner = false, noFollow = false } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 64 * 1024 * 1024) throw new TypeError("invalid_regular_file_limit");
  if (noFollow && typeof fs.constants.O_NOFOLLOW !== "number") throw new Error("regular_file_nofollow_unsupported");
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0) | (noFollow ? fs.constants.O_NOFOLLOW : 0);
  const fd = fs.openSync(file, flags);
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || !Number.isSafeInteger(info.size) || info.size < 0 || info.size > maxBytes || (privateOwner &&
      (typeof process.getuid !== "function" || info.uid !== process.getuid() || (info.mode & 0o077) !== 0))) {
      throw new Error("regular_file_integrity_required");
    }
    // Read at most limit+1, even if a same-owner writer grows the open inode.
    const bytes = Buffer.alloc(info.size + 1); let length = 0;
    while (length < bytes.length) {
      const amount = fs.readSync(fd, bytes, length, bytes.length - length, length);
      if (amount === 0) break;
      length += amount;
    }
    if (length > info.size || fs.fstatSync(fd).size !== length) throw new Error("regular_file_changed_during_read");
    return bytes.subarray(0, length);
  } finally { fs.closeSync(fd); }
}
