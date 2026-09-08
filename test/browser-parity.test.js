import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { compileSource } from "../index.js";
import { compileSourceBrowser } from "../docs/aml-browser.js";

function normalize(decisions) {
  return decisions.map(({ timestamp, ...rest }) => rest);
}

for (const file of [
  "examples/simple.aml",
  "examples/ai_assistant.aml",
  "examples/accessibility_first.aml",
  "conformance/allow.aml",
  "conformance/suppress.aml"
]) {
  test(`browser engine matches core compiler decisions: ${file}`, () => {
    const source = fs.readFileSync(file, "utf8");
    const core = compileSource(source);
    const browser = compileSourceBrowser(source);

    assert.deepEqual(browser.tokens, core.tokens);
    assert.deepEqual(browser.ast, core.ast);
    assert.deepEqual(browser.amt, core.amt);
    assert.deepEqual(normalize(browser.renderDecisions), normalize(core.renderDecisions));
  });
}
