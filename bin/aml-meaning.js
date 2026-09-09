#!/usr/bin/env node

import fs from "node:fs";
import { meaningFingerprint, compareMeaningFingerprints } from "../compiler/meaningFingerprint.js";

const [leftPath, rightPath] = process.argv.slice(2);

function usage() {
  console.error("Usage: aml-meaning <file.aml> [other.aml]");
  console.error("One file prints its deterministic meaning fingerprint.");
  console.error("Two files compare AMT meaning and exit 0 when equivalent, 1 when different.");
}

if (!leftPath) {
  usage();
  process.exit(2);
}

try {
  const leftSource = fs.readFileSync(leftPath, "utf8");
  if (!rightPath) {
    console.log(JSON.stringify({ file: leftPath, ...meaningFingerprint(leftSource) }, null, 2));
    process.exit(0);
  }

  const rightSource = fs.readFileSync(rightPath, "utf8");
  const report = compareMeaningFingerprints(leftSource, rightSource);
  console.log(JSON.stringify({ left_file: leftPath, right_file: rightPath, ...report }, null, 2));
  process.exit(report.equivalent ? 0 : 1);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
