#!/usr/bin/env node

import fs from "node:fs";
import { localizeRuntimeDisagreement } from "../protocol/runtimeDisagreement.js";

const [leftPath, rightPath] = process.argv.slice(2).filter(arg => !arg.startsWith("--"));
function value(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? null : null;
}

if (!leftPath || !rightPath) {
  console.error("Usage: aml-runtime-disagreement <left-transcript.json> <right-transcript.json> [--left-runtime name] [--right-runtime name]");
  process.exit(1);
}

try {
  const left = JSON.parse(fs.readFileSync(leftPath, "utf8"));
  const right = JSON.parse(fs.readFileSync(rightPath, "utf8"));
  const report = localizeRuntimeDisagreement(left, right, {
    left_runtime: value("--left-runtime"),
    right_runtime: value("--right-runtime")
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.equivalent ? 0 : 2;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
