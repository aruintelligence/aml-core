import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { compileAML, verifyBuildManifest } from "../index.js";

const timestamp = "2026-01-01T00:00:00.000Z";

test("AML build verification accepts an untouched compilation bundle", () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-verify-ok-"));
  compileAML("examples/simple.aml", outputDir, { timestamp });

  const verification = verifyBuildManifest(path.join(outputDir, "build_manifest.json"));

  assert.equal(verification.verified, true);
  assert.equal(verification.failed, 0);
  assert.ok(verification.passed >= 6);
});

test("AML build verification detects a modified artifact", () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-verify-tamper-"));
  compileAML("examples/simple.aml", outputDir, { timestamp });

  fs.appendFileSync(path.join(outputDir, "index.html"), "\n<!-- modified after build -->\n");

  const verification = verifyBuildManifest(path.join(outputDir, "build_manifest.json"));
  const htmlCheck = verification.checks.find(check => check.file === "index.html");

  assert.equal(verification.verified, false);
  assert.ok(verification.failed >= 1);
  assert.equal(htmlCheck.ok, false);
  assert.equal(htmlCheck.reason, "sha256-mismatch");
});
