// Test fixture only. A separate local directory demonstrates an atomic claim
// surviving an authority-store rollback; it is not a production trust service.
import fs from "node:fs";
import path from "node:path";

const DIGEST = /^[0-9a-f]{64}$/;

export function createTestingClaimOnce(directory) {
  return ({ protocol, claim_key_sha256, binding_sha256 }) => {
    if (protocol !== "aml-file-authority-external-claim/1" ||
        !DIGEST.test(claim_key_sha256) || !DIGEST.test(binding_sha256)) {
      throw Error("invalid_external_claim");
    }
    const file = path.join(directory, `${claim_key_sha256}.json`);
    let fd;
    try { fd = fs.openSync(file, "wx", 0o600); }
    catch (error) {
      if (error.code === "EEXIST") return false;
      throw error;
    }
    try {
      fs.writeFileSync(fd, JSON.stringify({ claim_key_sha256, binding_sha256 }) + "\n");
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    const directoryFd = fs.openSync(directory, "r");
    try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
    return true;
  };
}
