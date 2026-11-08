import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Integrate review-derived Python cases into BOTH Node full-suite discovery and
// targeted CI. The Node count is one wrapper, not the nested Python case count.
test("atomic provider review-derived persisted-state regressions (18 Python cases)", { timeout: 120_000 }, () => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const suite = fileURLToPath(new URL("./fixtures/action-contract-pilot-003-review.py", import.meta.url));
  const result = spawnSync("python3", ["-W", "error::ResourceWarning", suite], {
    cwd: root, encoding: "utf8", timeout: 110_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" }
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /Ran 18 tests/);
  assert.match(result.stderr, /^OK$/m); // Fail closed if unittest reports skipped cases.
});
