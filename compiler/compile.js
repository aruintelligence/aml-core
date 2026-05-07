// compiler/compile.js
// ĀML_CORE v1.0 — CLI entrypoint for compiler pipeline

import { compileAML } from "./compiler.js";

const inputPath =
  process.argv[2] || "examples/transmission-061.aml";

const outputDir =
  process.argv[3] || "dist";

try {
  const result = compileAML(inputPath, outputDir);

  console.log("ĀML compile complete.");
  console.log(`Input: ${result.input}`);
  console.log(`Output: ${result.output}`);
  console.log(`Tokens: ${result.tokens.length}`);
  console.log(`Render decisions: ${result.renderDecisions.length}`);
} catch (error) {
  console.error("ĀML compile failed.");
  console.error(error.message);
  process.exit(1);
}
