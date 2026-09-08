import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const paths = [
  "editors/vscode/package.json",
  "editors/vscode/language-configuration.json",
  "editors/vscode/syntaxes/aml.tmLanguage.json"
];

test("AML VS Code support files are valid JSON", () => {
  for (const file of paths) {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.ok(parsed && typeof parsed === "object", `${file} should parse as JSON`);
  }
});

test("AML VS Code extension registers the .aml extension", () => {
  const pkg = JSON.parse(fs.readFileSync("editors/vscode/package.json", "utf8"));
  assert.ok(pkg.contributes.languages[0].extensions.includes(".aml"));
});
