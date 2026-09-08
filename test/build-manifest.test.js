import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { compileAML } from "../index.js";

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

test("filesystem compilation emits a verifiable SHA-256 build manifest", () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-manifest-"));
  const timestamp = "2026-01-01T00:00:00.000Z";
  const result = compileAML("examples/simple.aml", outputDir, { timestamp });
  const manifestPath = path.join(outputDir, "build_manifest.json");

  assert.equal(fs.existsSync(manifestPath), true);

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  assert.equal(manifest.generated_at, timestamp);
  assert.equal(manifest.source.sha256, sha256(fs.readFileSync("examples/simple.aml", "utf8")));
  assert.equal(manifest.render_decision_count, result.renderDecisions.length);

  for (const [filename, metadata] of Object.entries(manifest.artifacts)) {
    const content = fs.readFileSync(path.join(outputDir, filename));
    assert.equal(metadata.sha256, sha256(content));
    assert.equal(metadata.bytes, content.byteLength);
  }
});
