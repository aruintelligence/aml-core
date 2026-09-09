#!/usr/bin/env node

import fs from "node:fs";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";
import { createInTotoSemanticReleaseStatement, verifyInTotoSemanticReleaseStatement } from "../compiler/inTotoSemanticRelease.js";

const args = process.argv.slice(2);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function usage() {
  console.error("Usage:\n  aml-release-proof <proof.json>\n  aml-release-proof in-toto <proof.json>\n  aml-release-proof verify-in-toto <statement.json>");
}

try {
  if (args.length === 1) {
    const proof = readJson(args[0]);
    const result = verifySemanticReleaseProof(proof);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }

  if (args.length === 2 && args[0] === "in-toto") {
    const proof = readJson(args[1]);
    const statement = createInTotoSemanticReleaseStatement(proof);
    console.log(JSON.stringify(statement, null, 2));
    process.exit(0);
  }

  if (args.length === 2 && args[0] === "verify-in-toto") {
    const statement = readJson(args[1]);
    const result = verifyInTotoSemanticReleaseStatement(statement);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }

  usage();
  process.exit(2);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
