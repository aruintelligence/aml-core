#!/usr/bin/env node

import fs from "node:fs";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";

const [proofPath, ...rest] = process.argv.slice(2);

if (!proofPath || rest.length) {
  console.error("Usage: aml-release-proof <proof.json>");
  process.exit(2);
}

try {
  const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  const result = verifySemanticReleaseProof(proof);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.verified ? 0 : 1);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
