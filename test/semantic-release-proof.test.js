import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  createMeaningManifest,
  signMeaningManifest,
  createMeaningLineage,
  appendMeaningLineage,
  createSemanticReleaseProof,
  verifySemanticReleaseProof
} from "../index.js";

const beforeSources = {
  "ui/card.aml": `transmission "release" {
  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }
}`,
  "ui/stable.aml": `transmission "stable" {
  engram stable {
    purpose: "Stay stable"
    attention_cost: 1
    restoration_value: 4
  }
}`,
  "ui/removed.aml": `transmission "removed" {
  engram old {
    purpose: "Old path"
    attention_cost: 1
    restoration_value: 2
  }
}`
};

const afterSources = {
  "ui/card.aml": `transmission "release" {
  engram card {
    purpose: "Create urgency"
    attention_cost: 4
    restoration_value: 3
  }
}`,
  "ui/stable.aml": beforeSources["ui/stable.aml"],
  "ui/added.aml": `transmission "added" {
  engram fresh {
    purpose: "New path"
    attention_cost: 1
    restoration_value: 5
  }
}`
};

function fixture() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const beforeManifest = createMeaningManifest(beforeSources);
  const afterManifest = createMeaningManifest(afterSources);
  const beforeAttestation = signMeaningManifest(beforeManifest, privateKeyPem, { signer: "release-bot", timestamp: "2026-09-08T20:00:00.000Z" });
  const afterAttestation = signMeaningManifest(afterManifest, privateKeyPem, { signer: "release-bot", timestamp: "2026-09-08T21:00:00.000Z" });
  let lineage = createMeaningLineage();
  lineage = appendMeaningLineage(lineage, beforeManifest, beforeAttestation);
  lineage = appendMeaningLineage(lineage, afterManifest, afterAttestation);
  const proof = createSemanticReleaseProof({
    before_manifest: beforeManifest,
    before_attestation: beforeAttestation,
    after_manifest: afterManifest,
    after_attestation: afterAttestation,
    lineage,
    before_sources: beforeSources,
    after_sources: afterSources,
    private_key_pem: privateKeyPem,
    signer: "release-bot",
    timestamp: "2026-09-08T21:05:00.000Z",
    release_id: "v-next",
    previous_release_id: "v-prev"
  });
  return { proof, privateKeyPem, beforeManifest, afterManifest, beforeAttestation, afterAttestation, lineage };
}

test("semantic release proof verifies a self-contained signed release transition", () => {
  const { proof } = fixture();
  const result = verifySemanticReleaseProof(proof);
  assert.equal(result.verified, true);
  assert.equal(result.attribution_bound, true);
  assert.equal(result.signer, "release-bot");
  assert.equal(result.release_id, "v-next");
  assert.deepEqual(result.change_summary, { added: 1, removed: 1, changed: 1, unchanged: 1 });
  assert.deepEqual(proof.changes.map(change => [change.path, change.kind]), [
    ["ui/added.aml", "added"],
    ["ui/card.aml", "changed"],
    ["ui/removed.aml", "removed"],
    ["ui/stable.aml", "unchanged"]
  ]);
});

test("semantic release proof binds detailed semantic diff and source snapshots", () => {
  const { proof } = fixture();
  const changed = proof.changes.find(change => change.kind === "changed");
  changed.semantic_diff.summary.changed = 999;
  assert.equal(verifySemanticReleaseProof(proof).verified, false);

  const second = fixture().proof;
  second.changes.find(change => change.kind === "changed").after_source = beforeSources["ui/card.aml"];
  assert.equal(verifySemanticReleaseProof(second).verified, false);

  const third = fixture().proof;
  third.changes.find(change => change.kind === "added").after_source += "\n// changed source text but same AMT";
  assert.equal(verifySemanticReleaseProof(third).verified, false);
});

test("semantic release proof binds summary, attribution, roots, and lineage head", () => {
  for (const mutate of [
    proof => { proof.change_summary.changed = 0; },
    proof => { proof.signer = "forged-signer"; },
    proof => { proof.generated_at = "2026-09-08T22:00:00.000Z"; },
    proof => { proof.after_manifest_root_sha256 = "0".repeat(64); },
    proof => { proof.lineage_head_sha256 = "0".repeat(64); }
  ]) {
    const { proof } = fixture();
    mutate(proof);
    assert.equal(verifySemanticReleaseProof(proof).verified, false);
  }
});

test("semantic release proof rejects nested signed-artifact and lineage tampering", () => {
  const first = fixture().proof;
  first.after_attestation.signer = "forged";
  assert.equal(verifySemanticReleaseProof(first).verified, false);

  const second = fixture().proof;
  second.lineage.entries[0].semantic_changed = true;
  assert.equal(verifySemanticReleaseProof(second).verified, false);

  const third = fixture().proof;
  third.lineage.entries.pop();
  assert.equal(verifySemanticReleaseProof(third).verified, false);
});

test("semantic release proof creation refuses lineage that does not terminate in the supplied releases", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const beforeManifest = createMeaningManifest(beforeSources);
  const afterManifest = createMeaningManifest(afterSources);
  const beforeAttestation = signMeaningManifest(beforeManifest, privateKeyPem, { timestamp: "2026-09-08T20:00:00.000Z" });
  const afterAttestation = signMeaningManifest(afterManifest, privateKeyPem, { timestamp: "2026-09-08T21:00:00.000Z" });
  let lineage = createMeaningLineage();
  lineage = appendMeaningLineage(lineage, beforeManifest, beforeAttestation);

  assert.throws(() => createSemanticReleaseProof({
    before_manifest: beforeManifest,
    before_attestation: beforeAttestation,
    after_manifest: afterManifest,
    after_attestation: afterAttestation,
    lineage,
    before_sources: beforeSources,
    after_sources: afterSources,
    private_key_pem: privateKeyPem
  }), /final two lineage entries/);
});

test("semantic release proof verifier fails closed on malformed public key and signature", () => {
  const first = fixture().proof;
  first.public_key_pem = "not a key";
  assert.equal(verifySemanticReleaseProof(first).verified, false);

  const second = fixture().proof;
  second.signature_base64 = "%%%";
  assert.equal(verifySemanticReleaseProof(second).verified, false);
});
