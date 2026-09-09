import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  createMeaningManifest,
  signMeaningManifest,
  createMeaningLineage,
  appendMeaningLineage,
  verifyMeaningLineage
} from "../index.js";

const keyPair = crypto.generateKeyPairSync("ed25519");
const privatePem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" });

function signed(sources, timestamp) {
  const manifest = createMeaningManifest(sources);
  const attestation = signMeaningManifest(manifest, privatePem, { signer: "release-engineering", timestamp });
  return { manifest, attestation };
}

function clone(value) {
  return structuredClone(value);
}

const v1 = { "ui/app.aml": `transmission "app" { engram card { purpose: "Explain clearly" attention_cost: 1 restoration_value: 4 } }` };
const v2 = { "ui/app.aml": `transmission "app" { engram card { purpose: "Explain clearly" attention_cost: 1 restoration_value: 4 } }` };
const v3 = { "ui/app.aml": `transmission "app" { engram card { purpose: "Create urgency" attention_cost: 3 restoration_value: 2 } }` };

test("semantic lineage links signed semantic roots append-only", () => {
  const a = signed(v1, "2026-09-08T23:20:00.000Z");
  const b = signed(v2, "2026-09-08T23:21:00.000Z");
  const c = signed(v3, "2026-09-08T23:22:00.000Z");

  let chain = createMeaningLineage();
  chain = appendMeaningLineage(chain, a.manifest, a.attestation);
  chain = appendMeaningLineage(chain, b.manifest, b.attestation);
  chain = appendMeaningLineage(chain, c.manifest, c.attestation);

  const result = verifyMeaningLineage(chain);
  assert.equal(result.verified, true);
  assert.equal(result.entries_verified, 3);
  assert.deepEqual(result.results.map(x => x.semantic_changed), [null, false, true]);
  assert.equal(result.results[2].signer, "release-engineering");
  assert.equal(result.head_manifest_root_sha256, c.manifest.root_sha256);
});

test("rewriting an old manifest breaks lineage verification", () => {
  const a = signed(v1, "2026-09-08T23:20:00.000Z");
  const b = signed(v3, "2026-09-08T23:21:00.000Z");
  let chain = appendMeaningLineage(createMeaningLineage(), a.manifest, a.attestation);
  chain = appendMeaningLineage(chain, b.manifest, b.attestation);

  const tampered = clone(chain);
  tampered.entries[0].manifest.files[0].fingerprint = "0".repeat(64);
  assert.equal(verifyMeaningLineage(tampered).verified, false);
});

test("swapping an attestation breaks embedded signed-root verification", () => {
  const a = signed(v1, "2026-09-08T23:20:00.000Z");
  const b = signed(v3, "2026-09-08T23:21:00.000Z");
  let chain = appendMeaningLineage(createMeaningLineage(), a.manifest, a.attestation);
  chain = appendMeaningLineage(chain, b.manifest, b.attestation);

  const tampered = clone(chain);
  tampered.entries[1].attestation = clone(a.attestation);
  const result = verifyMeaningLineage(tampered);
  assert.equal(result.verified, false);
  assert.equal(result.reason, "embedded_root_binding_mismatch");
});

test("deleting or reordering history breaks sequence/hash linkage", () => {
  const a = signed(v1, "2026-09-08T23:20:00.000Z");
  const b = signed(v3, "2026-09-08T23:21:00.000Z");
  const c = signed(v1, "2026-09-08T23:22:00.000Z");
  let chain = createMeaningLineage();
  for (const artifact of [a, b, c]) chain = appendMeaningLineage(chain, artifact.manifest, artifact.attestation);

  const deleted = clone(chain);
  deleted.entries.splice(1, 1);
  assert.equal(verifyMeaningLineage(deleted).verified, false);

  const reordered = clone(chain);
  [reordered.entries[1], reordered.entries[2]] = [reordered.entries[2], reordered.entries[1]];
  assert.equal(verifyMeaningLineage(reordered).verified, false);
});

test("lying about semantic change or parent root breaks lineage", () => {
  const a = signed(v1, "2026-09-08T23:20:00.000Z");
  const b = signed(v3, "2026-09-08T23:21:00.000Z");
  let chain = appendMeaningLineage(createMeaningLineage(), a.manifest, a.attestation);
  chain = appendMeaningLineage(chain, b.manifest, b.attestation);

  const flag = clone(chain);
  flag.entries[1].semantic_changed = false;
  assert.equal(verifyMeaningLineage(flag).reason, "semantic_change_flag_mismatch");

  const parent = clone(chain);
  parent.entries[1].previous_manifest_root_sha256 = "f".repeat(64);
  assert.equal(verifyMeaningLineage(parent).reason, "previous_manifest_root_mismatch");
});

test("invalid signed artifacts cannot be appended", () => {
  const a = signed(v1, "2026-09-08T23:20:00.000Z");
  const bad = clone(a.attestation);
  bad.signer = "rewritten";
  assert.throws(
    () => appendMeaningLineage(createMeaningLineage(), a.manifest, bad),
    /invalid signed Meaning Manifest artifact/
  );
});
