import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateActionProbes } from "../conformance/action-boundary-probes.js";
import { prepareCase, checkCase } from "../conformance/action-boundary-challenge-core.js";
import { cannedAnswer } from "./fixtures/canned-action-adapter.mjs";
import { runReferenceCase } from "../pilots/action-boundary/challenge-reference-adapter.mjs";

const manifest = JSON.parse(readFileSync(new URL("../conformance/action-boundary-challenge.json", import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL("../pilots/action-boundary/vectors.json", import.meta.url)));
const firstSeed = "0123456789abcdef0123456789abcdef";
const secondSeed = "fedcba9876543210fedcba9876543210";

test("seeded transformations are reproducible and alter proposal digests", () => {
  const first = generateActionProbes(manifest, vectors, firstSeed);
  assert.deepEqual(generateActionProbes(manifest, vectors, firstSeed), first);
  const second = generateActionProbes(manifest, vectors, secondSeed);
  assert.equal(first.rows.length, 6);
  assert.equal(new Set(first.rows.map(row => row.id)).size, 6);
  assert.notEqual(first.vectors.cases.at(-1).proposal_sha256, second.vectors.cases.at(-1).proposal_sha256);
  assert.deepEqual(vectors.policy.rules[0].resource, "team@example.test", "source contract is untouched");
  assert.throws(() => generateActionProbes(manifest, vectors, "not-a-seed"), /probe_seed/);
});

test("published answer lookup passes fixed inputs but fails all probes, while execution passes both", async () => {
  const { rows, vectors: expanded } = generateActionProbes(manifest, vectors, firstSeed);
  for (const row of manifest.cases) {
    const input = prepareCase(row, expanded);
    assert.deepEqual(checkCase(row, cannedAnswer(input), { status: 0 }, expanded), [], row.id);
  }
  for (const row of rows) {
    const input = prepareCase(row, expanded);
    assert.ok(checkCase(row, cannedAnswer(input), { status: 0 }, expanded).length > 0, row.id);
    assert.deepEqual(checkCase(row, await runReferenceCase(input), { status: 0 }, expanded), [], row.id);
  }
});
