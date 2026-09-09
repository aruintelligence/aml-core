import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const base = `transmission "demo" {
  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }
}`;

const sameMeaning = `// comment only
transmission "demo" {

  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }
}`;

const changedMeaning = `transmission "demo" {
  engram card {
    purpose: "Create urgency"
    attention_cost: 2
    restoration_value: 5
  }
}`;

function run(...args) {
  return spawnSync(process.execPath, ["bin/aml-meaning.js", ...args], {
    cwd: process.cwd(),
    encoding: "utf8"
  });
}

test("aml-meaning prints a fingerprint for one file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-meaning-"));
  const file = path.join(dir, "one.aml");
  fs.writeFileSync(file, base);
  const result = run(file);
  assert.equal(result.status, 0, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.protocol, "aml-meaning-fingerprint/1");
  assert.match(body.fingerprint, /^[a-f0-9]{64}$/);
});

test("aml-meaning exits 0 for equivalent meaning and 1 for changed meaning", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-meaning-"));
  const before = path.join(dir, "before.aml");
  const same = path.join(dir, "same.aml");
  const changed = path.join(dir, "changed.aml");
  fs.writeFileSync(before, base);
  fs.writeFileSync(same, sameMeaning);
  fs.writeFileSync(changed, changedMeaning);

  const equivalent = run(before, same);
  assert.equal(equivalent.status, 0, equivalent.stderr);
  assert.equal(JSON.parse(equivalent.stdout).equivalent, true);

  const different = run(before, changed);
  assert.equal(different.status, 1, different.stderr);
  assert.equal(JSON.parse(different.stdout).equivalent, false);
});
