#!/usr/bin/env node

// bin/aml.js
// ĀML_CORE v1.1 — Command-Line Interface

import fs from "fs";
import { compileAML, compileSource } from "../compiler/compiler.js";

const args = process.argv.slice(2);
const command = args[0];
const inputPath = args[1] || "examples/transmission-061.aml";
const outputDir = args[2] || "dist";

function showHelp() {
  console.log(`
ĀML — ĀRU Meaning Language

Usage:
  aml compile <file.aml> [outputDir]
  aml inspect <file.aml>
  aml validate <file.aml>
  aml help
  aml version

Commands:
  compile   Compile AML into HTML and accountability artifacts
  inspect   Compile in memory and print the Abstract Meaning Tree + render decisions
  validate  Parse and evaluate AML without writing output files
  help      Show this help message
  version   Show AML CLI version

Examples:
  aml compile examples/transmission-061.aml
  aml compile examples/ai_assistant.aml dist
  aml inspect examples/accessibility_first.aml
  aml validate examples/calm_checkout.aml
`);
}

function showVersion() {
  console.log("ĀML CLI v1.1.0");
}

function readSource(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

try {
  if (!command || command === "help" || command === "--help" || command === "-h") {
    showHelp();
    process.exit(0);
  }

  if (command === "version" || command === "--version" || command === "-v") {
    showVersion();
    process.exit(0);
  }

  if (command === "compile") {
    const result = compileAML(inputPath, outputDir);
    console.log("ĀML compile complete.");
    console.log(`Input: ${result.input}`);
    console.log(`Output: ${result.output}`);
    console.log(`Tokens: ${result.tokens.length}`);
    console.log(`Render decisions: ${result.renderDecisions.length}`);
    process.exit(0);
  }

  if (command === "inspect") {
    const result = compileSource(readSource(inputPath));
    console.log(JSON.stringify({
      input: inputPath,
      amt: result.amt,
      render_decisions: result.renderDecisions
    }, null, 2));
    process.exit(0);
  }

  if (command === "validate") {
    const result = compileSource(readSource(inputPath));
    console.log(`VALID: ${inputPath}`);
    console.log(`Tokens: ${result.tokens.length}`);
    console.log(`Render decisions: ${result.renderDecisions.length}`);
    process.exit(0);
  }

  console.error(`Unknown command: ${command}`);
  showHelp();
  process.exit(1);
} catch (error) {
  console.error("ĀML command failed.");
  console.error(error.message);
  process.exit(1);
}
