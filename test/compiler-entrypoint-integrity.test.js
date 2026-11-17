import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { verifyBuildManifest } from "../compiler/verifyBuild.js";
const root = fileURLToPath(new URL("../", import.meta.url));
const run = (args, cwd = root) => spawnSync(process.execPath, args, { cwd, encoding: "utf8", timeout: 30000 });
function temporary(fn) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-compiler-entry-")); try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); } }

test("all shipped compiler JavaScript files pass syntax checking, including the legacy path", () => {
  function walk(dir) { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const file = path.join(dir, e.name); if (e.isDirectory()) walk(file); else if (e.name.endsWith(".js")) { const p = run(["--check", file]); assert.equal(p.status, 0, `${e.name}: ${p.stderr}`); } } }
  walk(path.join(root, "compiler"));
});
test("canonical compiler import is not direct execution merely because the caller suffix matches", () => temporary(dir => {
  const target = pathToFileURL(path.join(root, "compiler/compiler.js")).href;
  const p = run(["--input-type=module", "-e", `process.argv[1]="unrelated-compiler.js"; const m=await import(${JSON.stringify(target)}); if(typeof m.compileAML!=="function") throw Error("missing API");`], dir);
  assert.equal(p.status, 0, p.stderr); assert.deepEqual(fs.readdirSync(dir), []);
}));
test("legacy CLI delegates exactly once to the canonical compiler and emits a verifiable build", () => temporary(dir => {
  const p = run(["compiler/aml-compiler.js", "examples/simple.aml", dir]);
  assert.equal(p.status, 0, p.stderr);
  assert.equal((p.stdout.match(/ĀML compile complete\./g) ?? []).length, 1);
  assert.equal(verifyBuildManifest(path.join(dir, "build_manifest.json")).verified, true);
  assert.ok(fs.existsSync(path.join(dir, "index.html"))); assert.ok(fs.existsSync(path.join(dir, "render_decision.json")));
}));
test("legacy CLI missing input rejects without emitting or initializing an output directory", () => temporary(dir => {
  const output = path.join(dir, "absent-output"); const p = run(["compiler/aml-compiler.js", path.join(dir, "absent-input.aml"), output]);
  assert.equal(p.status, 1); assert.match(p.stderr, /compile failed/); assert.equal(fs.existsSync(output), false);
}));
