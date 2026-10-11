#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { verifyStudioBundle } from "../pilots/action-boundary/studio-bundle.mjs";

if (process.argv.length !== 3) {
  console.error("Usage: node scripts/verify-action-studio-bundle.mjs <bundle.json>");
  process.exitCode = 2;
} else {
  try {
    const bundle = JSON.parse(readFileSync(process.argv[2], "utf8"));
    const result = verifyStudioBundle(bundle);
    console.log(JSON.stringify(result, null, 2));
    if (!result.consistent) process.exitCode = 1;
  } catch (error) {
    console.error(JSON.stringify({ protocol: "aml-action-studio-verification/1",
      consistent: false, failures: ["unreadable_bundle"], detail: error.message }));
    process.exitCode = 1;
  }
}
