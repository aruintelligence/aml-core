#!/usr/bin/env node
// Keep the static builder's report and module URLs tied to the bytes they load.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const reportUrl = new URL("../docs/guarded-tool-rehearsal.json", import.meta.url);
const scriptUrl = new URL("../docs/agent-start.js", import.meta.url);
const pageUrl = new URL("../docs/agent-start.html", import.meta.url);
const fingerprint = content => createHash("sha256").update(content).digest("hex").slice(0, 12);

function replaceOne(content, expression, replacement) {
  const matches = content.match(expression);
  if (matches?.length !== 1) throw new Error(`Expected one asset URL, found ${matches?.length ?? 0}`);
  return content.replace(expression, replacement);
}

export function versionAgentStartAssets(report, script, page) {
  const reportHash = fingerprint(report);
  const expectedScript = replaceOne(script, /guarded-tool-rehearsal\.json\?v=[0-9a-f]{12}/g,
    `guarded-tool-rehearsal.json?v=${reportHash}`);
  const scriptHash = fingerprint(expectedScript);
  const expectedPage = replaceOne(page, /agent-start\.js\?v=[0-9a-f]{12}/g,
    `agent-start.js?v=${scriptHash}`);
  return { script: expectedScript, page: expectedPage, reportHash, scriptHash };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode] = process.argv.slice(2);
  if (process.argv.length !== 3 || !["--write", "--check"].includes(mode)) {
    throw new Error("Use --write to refresh the URLs or --check to verify them");
  }
  const [report, script, page] = await Promise.all([
    readFile(reportUrl, "utf8"), readFile(scriptUrl, "utf8"), readFile(pageUrl, "utf8")
  ]);
  const versioned = versionAgentStartAssets(report, script, page);
  if (mode === "--check") {
    assert.equal(script, versioned.script, "Builder report URL is stale; run --write");
    assert.equal(page, versioned.page, "Builder script URL is stale; run --write");
    console.log(`Agent builder assets match report ${versioned.reportHash} and script ${versioned.scriptHash}.`);
  } else {
    await writeFile(scriptUrl, versioned.script, "utf8");
    await writeFile(pageUrl, versioned.page, "utf8");
    console.log(`Refreshed agent builder assets: report ${versioned.reportHash}, script ${versioned.scriptHash}.`);
  }
}
