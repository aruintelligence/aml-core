// compiler/compiler.js
// ĀML_CORE v1.0 — End-to-End Compiler Pipeline

import fs from "fs";
import path from "path";

import { tokenize } from "./lexer.js";
import { parse } from "./parser.js";
import { buildAMT } from "./amtBuilder.js";
import { evaluateRenderDecisions } from "./renderEvaluator.js";
import { generateHTML } from "./htmlGenerator.js";

export function compileAML(inputPath, outputDir = "dist") {
  const source = fs.readFileSync(inputPath, "utf8");

  const tokens = tokenize(source);
  const ast = parse(tokens);
  const amt = buildAMT(ast);
  const renderDecisions = evaluateRenderDecisions(amt);
  const html = generateHTML(amt, renderDecisions);

  fs.mkdirSync(outputDir, { recursive: true });

  fs.writeFileSync(
    path.join(outputDir, "index.html"),
    html
  );

  fs.writeFileSync(
    path.join(outputDir, "tokens.json"),
    JSON.stringify(tokens, null, 2)
  );

  fs.writeFileSync(
    path.join(outputDir, "ast.json"),
    JSON.stringify(ast, null, 2)
  );

  fs.writeFileSync(
    path.join(outputDir, "amt.json"),
    JSON.stringify(amt, null, 2)
  );

  fs.writeFileSync(
    path.join(outputDir, "render_decision.json"),
    JSON.stringify(renderDecisions, null, 2)
  );

  return {
    input: inputPath,
    output: outputDir,
    tokens,
    ast,
    amt,
    renderDecisions,
    html
  };
}

const isDirectRun =
  process.argv[1] &&
  process.argv[1].endsWith("compiler.js");

if (isDirectRun) {
  const inputPath =
    process.argv[2] || "examples/transmission-061.aml";

  const outputDir =
    process.argv[3] || "dist";

  const result = compileAML(inputPath, outputDir);

  console.log("ĀML compile complete.");
  console.log(`Input: ${result.input}`);
  console.log(`Output: ${result.output}`);
  console.log(`Render decisions: ${result.renderDecisions.length}`);
}
