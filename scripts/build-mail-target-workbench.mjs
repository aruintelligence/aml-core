#!/usr/bin/env node
// Keep the browser's schema parser byte-identical to the trusted Node adapter.
import assert from "node:assert/strict";
import fs from "node:fs";

const source = new URL("../pilots/action-boundary/mail-target-core.mjs", import.meta.url);
const published = new URL("../docs/mail-target-core.mjs", import.meta.url);
const bytes = fs.readFileSync(source);
if (process.argv.includes("--check")) {
  assert.deepEqual(fs.readFileSync(published), bytes, "Browser schema parser is stale");
  console.log("Verified byte-identical browser mail-target core");
} else {
  fs.writeFileSync(published, bytes);
  console.log("Wrote docs/mail-target-core.mjs");
}
