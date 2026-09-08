// compiler/verifyBuild.js
// Verify an ĀML build_manifest.json against source and emitted artifact bytes.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

export function verifyBuildManifest(manifestPath) {
  const absoluteManifest = path.resolve(manifestPath);
  const buildDir = path.dirname(absoluteManifest);
  const manifest = JSON.parse(fs.readFileSync(absoluteManifest, "utf8"));
  const checks = [];

  function checkFile(kind, filename, expectedHash, expectedBytes = null) {
    const filePath = kind === "source"
      ? path.resolve(process.cwd(), filename)
      : path.join(buildDir, filename);

    if (!fs.existsSync(filePath)) {
      checks.push({ kind, file: filename, ok: false, reason: "missing" });
      return;
    }

    const content = fs.readFileSync(filePath);
    const actualHash = sha256(content);
    const hashOk = actualHash === expectedHash;
    const bytesOk = expectedBytes === null || content.byteLength === expectedBytes;

    checks.push({
      kind,
      file: filename,
      ok: hashOk && bytesOk,
      expected_sha256: expectedHash,
      actual_sha256: actualHash,
      expected_bytes: expectedBytes,
      actual_bytes: content.byteLength,
      reason: hashOk && bytesOk ? "verified" : !hashOk ? "sha256-mismatch" : "byte-count-mismatch"
    });
  }

  if (!manifest?.source?.path || !manifest?.source?.sha256) {
    throw new Error("Invalid ĀML build manifest: missing source path or SHA-256 digest.");
  }

  checkFile("source", manifest.source.path, manifest.source.sha256);

  for (const [filename, metadata] of Object.entries(manifest.artifacts || {})) {
    checkFile("artifact", filename, metadata.sha256, metadata.bytes ?? null);
  }

  const failed = checks.filter(check => !check.ok);

  return {
    protocol: "ĀML Build Verification",
    manifest: manifestPath,
    verified: failed.length === 0,
    checks,
    passed: checks.length - failed.length,
    failed: failed.length
  };
}
