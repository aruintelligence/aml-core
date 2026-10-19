// Test fixture only. This separate local store serializes epoch advances and
// claims to demonstrate rollback resistance; it is not a production service.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

const DIGEST = /^[0-9a-f]{64}$/;
const sync = directory => {
  const fd = fs.openSync(directory, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
};

export function createTestingEpochAnchor(directory) {
  const epochs = path.join(directory, "epochs");
  const claims = path.join(directory, "claims");
  for (const child of [epochs, claims]) fs.mkdirSync(child, { recursive: true, mode: 0o700 });

  function locked(action) {
    const lock = path.join(directory, "anchor.lock");
    fs.mkdirSync(lock, { mode: 0o700 });
    sync(directory);
    let completed = false;
    try {
      const result = action();
      completed = true;
      return result;
    } finally {
      if (completed) {
        fs.rmdirSync(lock);
        sync(directory);
      }
    }
  }

  function epochFor(issuer) {
    const file = path.join(epochs, `${issuer}.json`);
    let record;
    try { record = JSON.parse(fs.readFileSync(file, "utf8")); }
    catch (error) {
      if (error.code === "ENOENT") return 0;
      throw error;
    }
    if (record.protocol !== "aml-testing-external-epoch/1" ||
        record.issuer_sha256 !== issuer || !Number.isSafeInteger(record.epoch) ||
        record.epoch <= 0) throw Error("invalid_testing_epoch");
    return record.epoch;
  }

  return {
    advanceEpoch({ protocol, issuer_sha256, expected_epoch, next_epoch }) {
      if (protocol !== "aml-file-authority-external-epoch/1" ||
          !DIGEST.test(issuer_sha256) || !Number.isSafeInteger(expected_epoch) ||
          expected_epoch < 0 || !Number.isSafeInteger(next_epoch) ||
          next_epoch !== expected_epoch + 1) throw Error("invalid_external_epoch");
      return locked(() => {
        if (epochFor(issuer_sha256) !== expected_epoch) return false;
        const file = path.join(epochs, `${issuer_sha256}.json`);
        const temp = `${file}.${randomUUID()}.tmp`;
        const fd = fs.openSync(temp, "wx", 0o600);
        try {
          fs.writeFileSync(fd, JSON.stringify({ protocol: "aml-testing-external-epoch/1",
            issuer_sha256, epoch: next_epoch }) + "\n");
          fs.fsyncSync(fd);
        } finally { fs.closeSync(fd); }
        fs.renameSync(temp, file);
        sync(epochs);
        return true;
      });
    },
    claimOnce({ protocol, claim_key_sha256, binding_sha256, issuer_sha256, epoch }) {
      if (protocol !== "aml-file-authority-external-claim/2" ||
          !DIGEST.test(claim_key_sha256) || !DIGEST.test(binding_sha256) ||
          !DIGEST.test(issuer_sha256) || !Number.isSafeInteger(epoch) || epoch < 0) {
        throw Error("invalid_external_claim");
      }
      return locked(() => {
        if (epochFor(issuer_sha256) !== epoch) return false;
        const file = path.join(claims, `${claim_key_sha256}.json`);
        const fd = (() => {
          try { return fs.openSync(file, "wx", 0o600); }
          catch (error) {
            if (error.code === "EEXIST") return null;
            throw error;
          }
        })();
        if (fd === null) return false;
        try {
          fs.writeFileSync(fd, JSON.stringify({ claim_key_sha256, binding_sha256,
            issuer_sha256, epoch }) + "\n");
          fs.fsyncSync(fd);
        } finally { fs.closeSync(fd); }
        sync(claims);
        return true;
      });
    }
  };
}
