import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { checkExternalVerifierKit } from "../scripts/check-external-verifier-kit.mjs";

test("verifier kit rejects unsafe manifest paths before any outside-file read", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-kit-path-"));
  const root = path.join(parent, "kit"); fs.mkdirSync(root);
  const outside = path.join(parent, "public-synthetic.txt");
  const body = "synthetic public test data"; fs.writeFileSync(outside, body);
  const manifest = { schema: "aml-external-verifier-kit/1", reference_code_included: false,
    file_count: 1, files: [{ path: "../public-synthetic.txt", bytes: Buffer.byteLength(body),
      sha256: crypto.createHash("sha256").update(body).digest("hex") }] };
  fs.writeFileSync(path.join(root, "manifest.json"), JSON.stringify(manifest));
  fs.writeFileSync(path.join(root, "SHA256SUMS"), "");
  const original = fs.readFileSync; let outsideReads = 0;
  fs.readFileSync = function(file, ...args) { if (String(file) === outside) outsideReads++; return original.call(this, file, ...args); };
  try {
    const result = checkExternalVerifierKit(root);
    assert.equal(result.valid, false);
    assert.ok(result.failures.includes("unsafe path: ../public-synthetic.txt"));
    assert.equal(outsideReads, 0, "rejecting the result must also prevent the rejected filesystem access");
  } finally { fs.readFileSync = original; fs.rmSync(parent, { recursive: true, force: true }); }
});
