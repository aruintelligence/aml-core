import test from "node:test";
import assert from "node:assert/strict";

import { createMeaningManifest, verifyMeaningManifest } from "../index.js";

const a = `transmission "a" {
  engram card {
    purpose: "Explain A"
    attention_cost: 1
    restoration_value: 3
  }
}`;
const b = `transmission "b" {
  engram card {
    purpose: "Explain B"
    attention_cost: 2
    restoration_value: 4
  }
}`;

const sources = {
  "ui/a.aml": a,
  "ui/b.aml": b
};

test("Meaning Manifest is deterministic regardless of input object order", () => {
  const left = createMeaningManifest(sources);
  const right = createMeaningManifest({ "ui/b.aml": b, "ui/a.aml": a });
  assert.deepEqual(left, right);
  assert.equal(left.protocol, "aml-meaning-manifest/1");
  assert.equal(left.material_protocol, "aml-meaning-manifest-material/1");
  assert.equal(left.fingerprint_protocol, "aml-meaning-fingerprint/1");
  assert.equal(left.file_count, 2);
  assert.deepEqual(left.files.map(file => file.path), ["ui/a.aml", "ui/b.aml"]);
  assert.match(left.root_sha256, /^[a-f0-9]{64}$/);
});

test("Meaning Manifest verifies an exact unchanged source set", () => {
  const manifest = createMeaningManifest(sources);
  const result = verifyMeaningManifest(manifest, sources);
  assert.equal(result.verified, true);
  assert.equal(result.mismatches.length, 0);
  assert.equal(result.declared_root_valid, true);
  assert.equal(result.source_root_valid, true);
});

test("Meaning Manifest detects compiled meaning mutation", () => {
  const manifest = createMeaningManifest(sources);
  const result = verifyMeaningManifest(manifest, {
    ...sources,
    "ui/a.aml": a.replace("Explain A", "Create urgency")
  });
  assert.equal(result.verified, false);
  assert.equal(result.reason, "file_fingerprint_mismatch");
  assert.deepEqual(result.mismatches.map(item => item.path), ["ui/a.aml"]);
});

test("Meaning Manifest rejects missing or extra source paths", () => {
  const manifest = createMeaningManifest(sources);
  assert.equal(verifyMeaningManifest(manifest, { "ui/a.aml": a }).reason, "source_set_mismatch");
  assert.equal(verifyMeaningManifest(manifest, { ...sources, "ui/c.aml": a }).reason, "source_set_mismatch");
});

test("Meaning Manifest rejects reordered, duplicate, and unsafe declared paths", () => {
  const manifest = createMeaningManifest(sources);
  const reordered = structuredClone(manifest);
  reordered.files.reverse();
  assert.equal(verifyMeaningManifest(reordered, sources).reason, "manifest_paths_not_sorted");

  const duplicate = structuredClone(manifest);
  duplicate.files[1].path = duplicate.files[0].path;
  assert.equal(verifyMeaningManifest(duplicate, sources).reason, "duplicate_manifest_path");

  const unsafe = structuredClone(manifest);
  unsafe.files[0].path = "../escape.aml";
  assert.equal(verifyMeaningManifest(unsafe, sources).verified, false);
});

test("Meaning Manifest rejects malformed root and fingerprint fields", () => {
  const manifest = createMeaningManifest(sources);
  assert.equal(verifyMeaningManifest({ ...manifest, root_sha256: "nope" }, sources).reason, "invalid_manifest_root");

  const badFingerprint = structuredClone(manifest);
  badFingerprint.files[0].fingerprint = "nope";
  assert.equal(verifyMeaningManifest(badFingerprint, sources).reason, "invalid_file_fingerprint");
});
