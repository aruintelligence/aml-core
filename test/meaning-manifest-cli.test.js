import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const cli = path.resolve("bin/aml-meaning.js");
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

function run(cwd, ...args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd, encoding: "utf8" });
}

test("aml-meaning manifest creates a verifiable project meaning lock", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-meaning-manifest-"));
  fs.mkdirSync(path.join(dir, "ui"));
  fs.writeFileSync(path.join(dir, "ui", "a.aml"), a);
  fs.writeFileSync(path.join(dir, "ui", "b.aml"), b);

  const created = run(dir, "manifest", "ui/b.aml", "ui/a.aml");
  assert.equal(created.status, 0, created.stderr);
  const manifest = JSON.parse(created.stdout);
  assert.deepEqual(manifest.files.map(file => file.path), ["ui/a.aml", "ui/b.aml"]);
  fs.writeFileSync(path.join(dir, "aml-meaning-lock.json"), JSON.stringify(manifest, null, 2));

  const verified = run(dir, "verify-manifest", "aml-meaning-lock.json");
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stdout).verified, true);
});

test("aml-meaning verify-manifest exits 1 after compiled meaning drifts", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-meaning-manifest-"));
  fs.mkdirSync(path.join(dir, "ui"));
  fs.writeFileSync(path.join(dir, "ui", "a.aml"), a);
  fs.writeFileSync(path.join(dir, "ui", "b.aml"), b);

  const created = run(dir, "manifest", "ui/a.aml", "ui/b.aml");
  assert.equal(created.status, 0, created.stderr);
  fs.writeFileSync(path.join(dir, "aml-meaning-lock.json"), created.stdout);
  fs.writeFileSync(path.join(dir, "ui", "a.aml"), a.replace("Explain A", "Create urgency"));

  const verified = run(dir, "verify-manifest", "aml-meaning-lock.json");
  assert.equal(verified.status, 1, verified.stderr);
  const report = JSON.parse(verified.stdout);
  assert.equal(report.verified, false);
  assert.deepEqual(report.mismatches.map(item => item.path), ["ui/a.aml"]);
});

test("aml-meaning manifest refuses files outside the current project root", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-meaning-manifest-"));
  // A shared predictable /tmp filename could be precreated as a symlink.
  const outsideDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-meaning-outside-"));
  const outside = path.join(outsideDirectory, "outside.aml");
  assert.notEqual(path.dirname(outside), os.tmpdir());
  if (process.platform !== "win32") assert.equal(fs.statSync(outsideDirectory).mode & 0o077, 0);
  fs.writeFileSync(outside, a, { flag: "wx", mode: 0o600 });
  const result = run(dir, "manifest", outside);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /inside the current working directory/);
});
