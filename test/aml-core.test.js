import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { compileAML } from "../compiler/compiler.js";
import { ethicalRenderGate } from "../runtime/ethicalRenderGate.js";

test("EthicalRenderGate allows restorative elements", () => {
  const result = ethicalRenderGate({
    animation_intensity: 1,
    cognitive_load: 1,
    interaction_interruptions: 1,
    reading_complexity: 1,
    visual_noise: 1,
    clarity: 9,
    usefulness: 9,
    emotional_regulation: 9,
    continuity: 9,
    aesthetic_coherence: 9
  });

  assert.equal(result.render_allowed, true);
  assert.equal(result.fallback_triggered, false);
  assert.ok(result.restoration_value > result.attention_cost);
});

test("EthicalRenderGate suppresses attention-heavy elements", () => {
  const result = ethicalRenderGate({
    animation_intensity: 10,
    cognitive_load: 10,
    interaction_interruptions: 10,
    reading_complexity: 10,
    visual_noise: 10,
    clarity: 1,
    usefulness: 1,
    emotional_regulation: 1,
    continuity: 1,
    aesthetic_coherence: 1
  });

  assert.equal(result.render_allowed, false);
  assert.equal(result.fallback_triggered, true);
  assert.ok(result.attention_cost > result.restoration_value);
});

test("compiler produces inspectable artifacts", () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-core-"));
  const result = compileAML("examples/simple.aml", outputDir);

  assert.ok(result.tokens.length > 0);
  assert.ok(result.renderDecisions.length > 0);
  for (const file of ["index.html", "tokens.json", "ast.json", "amt.json", "render_decision.json"]) {
    assert.equal(fs.existsSync(path.join(outputDir, file)), true, `${file} should exist`);
  }
});
