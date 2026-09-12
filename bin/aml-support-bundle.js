#!/usr/bin/env node

import fs from "node:fs";
import { createAmlSupportBundle } from "../tooling/supportBundle.js";

const bundle = createAmlSupportBundle();
const outputPath = process.argv[2] || null;
const json = `${JSON.stringify(bundle, null, 2)}\n`;

if (outputPath) {
  fs.writeFileSync(outputPath, json);
  console.log(`WROTE: ${outputPath}`);
} else {
  process.stdout.write(json);
}

process.exit(bundle.healthy ? 0 : 1);
