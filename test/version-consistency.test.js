import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const packageJson = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const capabilities = JSON.parse(fs.readFileSync(new URL("../AML_CAPABILITIES.json", import.meta.url), "utf8"));
const cli = fs.readFileSync(new URL("../bin/aml.js", import.meta.url), "utf8");

test("package, capability manifest, and CLI report the same AML version", () => {
  assert.equal(capabilities.version, packageJson.version);
  assert.match(cli, new RegExp(`ĀML CLI v${packageJson.version.replaceAll(".", "\\.")}(?:\\b|\")`));
});
