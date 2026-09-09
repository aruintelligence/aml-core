import test from "node:test";
import assert from "node:assert/strict";
import {
  createContentAddressedBundle,
  verifyContentAddressedBundle,
  hashContent
} from "../index.js";

test("valid content-addressed bundle still verifies", () => {
  const bundle = createContentAddressedBundle({
    "a.json": { a: 1 },
    "b.txt": "hello"
  });
  assert.deepEqual(verifyContentAddressedBundle(bundle), {
    valid: true,
    reason: null,
    root: bundle.root
  });
});

test("content bundle rejects index-only phantom artifacts even with refreshed root", () => {
  const bundle = createContentAddressedBundle({ "a.txt": "alpha" });
  const forged = structuredClone(bundle);
  forged.index["ghost.txt"] = hashContent("ghost");
  forged.root = hashContent(forged.index);

  const result = verifyContentAddressedBundle(forged);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "index_file_set_mismatch");
});

test("content bundle rejects file-only artifacts", () => {
  const bundle = createContentAddressedBundle({ "a.txt": "alpha" });
  const forged = structuredClone(bundle);
  forged.files["extra.txt"] = {
    hash: hashContent("extra"),
    value: "extra"
  };

  const result = verifyContentAddressedBundle(forged);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "index_file_set_mismatch");
});

test("content bundle verifier fails closed on malformed structures", () => {
  const bundle = createContentAddressedBundle({ "a.txt": "alpha" });
  const cases = [
    { ...bundle, files: null },
    { ...bundle, index: [] },
    { ...bundle, root: "not-a-hash" },
    { ...bundle, files: { "a.txt": null } },
    { ...bundle, files: { "a.txt": { hash: "bad", value: "alpha" } } },
    { ...bundle, index: { "a.txt": "bad" } }
  ];

  for (const candidate of cases) {
    assert.doesNotThrow(() => verifyContentAddressedBundle(candidate));
    assert.equal(verifyContentAddressedBundle(candidate).valid, false);
  }
});
