import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

test("authorization-path matrix exercises 27 Python cases and retains caller-misuse limits", { timeout: 120_000 }, () => {
  const result = spawnSync("python3", ["-W", "error::ResourceWarning",
    fileURLToPath(new URL("./fixtures/action-boundary-authorization-paths.py", import.meta.url))], {
    cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8", timeout: 110_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" }
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /Ran 27 tests/);
  assert.match(result.stderr, /^OK$/m); // Skipped cases cannot silently pass.
});
