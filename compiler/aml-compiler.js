#!/usr/bin/env node
// Compatibility CLI for the original, truncated prototype path.
// Delegate to the canonical package compiler; do not maintain a second grammar,
// policy evaluator or HTML generator. The incomplete original is retained in Git.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compileAML } from "./compiler.js";

const isDirectRun = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) {
  try {
    const result = compileAML(process.argv[2] || "examples/simple.aml", process.argv[3] || "dist");
    console.log("ĀML compile complete.");
    console.log(`Input: ${result.input}`);
    console.log(`Output: ${result.output}`);
    console.log(`Render decisions: ${result.renderDecisions.length}`);
    console.log(`Manifest: ${path.join(result.output, "build_manifest.json")}`);
  } catch (error) {
    console.error("ĀML compile failed.");
    console.error(error.message);
    process.exitCode = 1;
  }
}
