import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { compileAML } from "../compiler/compiler.js";

const examples = [
  "examples/simple.aml",
  "examples/transmission-061.aml",
  "examples/ethical_ads.aml",
  "examples/focus_mode.aml",
  "examples/social_feed.aml",
  "examples/learning_mode.aml",
  "examples/accessibility_first.aml",
  "examples/ai_assistant_response.aml",
  "examples/calm_checkout.aml"
];

for (const example of examples) {
  test(`example compiles with accountability artifacts: ${example}`, () => {
    const slug = path.basename(example, ".aml");
    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), `aml-${slug}-`));
    const result = compileAML(example, outputDir);

    assert.ok(result.tokens.length > 0, "compiler should produce tokens");
    assert.ok(result.renderDecisions.length > 0, "compiler should produce at least one render decision");

    for (const artifact of [
      "index.html",
      "tokens.json",
      "ast.json",
      "amt.json",
      "render_decision.json"
    ]) {
      assert.equal(
        fs.existsSync(path.join(outputDir, artifact)),
        true,
        `${artifact} should exist for ${example}`
      );
    }
  });
}
