import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { runEvidenceDrill } from "../runtime/evidenceDrill.js";

const shares = [0, 1, 2].map(index =>
  JSON.parse(fs.readFileSync(new URL(`../independent/vectors/shards-v1/share-${index}.json`, import.meta.url), "utf8")));
const trust = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/trusted-policy.json", import.meta.url), "utf8"));

test("full rehearsal checks every pair against an externally remembered head", () => {
  const report = runEvidenceDrill(shares, trust);
  assert.equal(report.ready, true);
  assert.equal(report.health, "ready");
  assert.equal(report.passed_pairs, 3);
  assert.deepEqual(report.pairs.map(pair => pair.shares), [[0, 1], [0, 2], [1, 2]]);
  assert.equal(report.subject.accepted_head_bound, true);
  assert.equal(report.policy_hint_trusted, false);
  assert.equal(report.subject.payload_sha512, shares[0].payload_sha512);
});

test("one damaged share is recoverable but fails the readiness drill", () => {
  const damaged = structuredClone(shares);
  damaged[0].segment_base64 = "broken";
  const report = runEvidenceDrill(damaged, trust);
  assert.equal(report.ready, false);
  assert.equal(report.recovery_possible, true);
  assert.equal(report.health, "degraded");
  assert.equal(report.passed_pairs, 1);
  assert.deepEqual(report.pairs.filter(pair => pair.recovered).map(pair => pair.shares), [[1, 2]]);
  damaged[1].segment_base64 = "broken";
  const lost = runEvidenceDrill(damaged, trust);
  assert.equal(lost.recovery_possible, false);
  assert.equal(lost.health, "unrecoverable");
});

test("rehearsal distinguishes trusted recovery from rollback protection", () => {
  const { accepted_head, ...unboundedTrust } = trust;
  const unbounded = runEvidenceDrill(shares, unboundedTrust);
  assert.equal(unbounded.ready, false);
  assert.equal(unbounded.recovery_possible, true);
  assert.equal(unbounded.health, "unbounded");
  assert.equal(unbounded.reason, "accepted_head_required_for_drill");
  const fork = runEvidenceDrill(shares, { ...trust,
    accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } });
  assert.equal(fork.recovery_possible, false);
  assert.equal(fork.health, "unrecoverable");
  assert.equal(runEvidenceDrill(shares, null).reason, "external_trust_required");
});

test("misidentified or missing slots are visible in the report", () => {
  const swapped = runEvidenceDrill([shares[1], shares[0], shares[2]], trust);
  assert.equal(swapped.health, "unrecoverable");
  assert.equal(swapped.passed_pairs, 0);
  const missing = runEvidenceDrill([null, shares[1], shares[2]], trust);
  assert.equal(missing.health, "degraded");
  assert.equal(missing.passed_pairs, 1);
});
