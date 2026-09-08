// compiler/compiler.js
// ĀML_CORE v1.1 — Pure source pipeline + filesystem compiler

import fs from "fs";
import path from "path";

import { tokenize } from "./lexer.js";
import { parse } from "./parser.js";
import { buildAMT } from "./amtBuilder.js";
import { evaluateRenderDecisions } from "./renderEvaluator.js";
import { generateHTML } from "./htmlGenerator.js";

/**
 * Compile AML source text entirely in memory.
 *
 * options.timestamp can be set to an ISO timestamp to make accountability
 * artifacts reproducible across runs.
 */
export function compileSource(source, options = {}) {
  if (typeof source !== "string") {
    throw new TypeError("ĀML source must be a string.");
  }

  const tokens = tokenize(source);
  const ast = parse(tokens);
  const amt = buildAMT(ast);
  const renderDecisions = evaluateRenderDecisions(amt, options);
  const html = generateHTML(amt, renderDecisions);

  return {
    tokens,
    ast,
    amt,
    renderDecisions,
    html
  };
}

/**
 * Compile an AML file and emit browser + accountability artifacts.
 */
export function compileAML(inputPath, outputDir = "dist", options = {}) {
  const source = fs.readFileSync(inputPath, "utf8");
  const compiled = compileSource(source, options);

  fs.mkdirSync(outputDir, { recursive: true });

  fs.writeFileSync(path.join(outputDir, "index.html"), compiled.html);
  fs.writeFileSync(path.join(outputDir, "tokens.json"), JSON.stringify(compiled.tokens, null, 2));
  fs.writeFileSync(path.join(outputDir, "ast.json"), JSON.stringify(compiled.ast, null, 2));
  fs.writeFileSync(path.join(outputDir, "amt.json"), JSON.stringify(compiled.amt, null, 2));
  fs.writeFileSync(
    path.join(outputDir, "render_decision.json"),
    JSON.stringify(compiled.renderDecisions, null, 2)
  );

  return {
    input: inputPath,
    output: outputDir,
    ...compiled
  };
}

const isDirectRun = process.argv[1] && process.argv[1].endsWith("compiler.js");

if (isDirectRun) {
  const inputPath = process.argv[2] || "examples/transmission-061.aml";
  const outputDir = process.argv[3] || "dist";
  const result = compileAML(inputPath, outputDir);

  console.log("ĀML compile complete.");
  console.log(`Input: ${result.input}`);
  console.log(`Output: ${result.output}`);
  console.log(`Render decisions: ${result.renderDecisions.length}`);
}
