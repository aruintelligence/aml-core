#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const workflowsDir = path.join(root, ".github", "workflows");
const failures = [];
const inspected = [];

function topLevelTriggers(text) {
  const lines = text.split(/\r?\n/);
  const onIndex = lines.findIndex((line) => /^on:\s*/.test(line));
  if (onIndex < 0) return [];

  const inline = lines[onIndex].replace(/^on:\s*/, "").trim();
  if (inline) {
    return [...inline.matchAll(/[A-Za-z_][A-Za-z0-9_-]*/g)].map((m) => m[0]);
  }

  const triggers = [];
  for (let i = onIndex + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(line)) break;
    const match = line.match(/^  ([A-Za-z_][A-Za-z0-9_-]*):/);
    if (match) triggers.push(match[1]);
  }
  return triggers;
}

const files = fs.readdirSync(workflowsDir)
  .filter((name) => /\.ya?ml$/i.test(name))
  .sort();

for (const name of files) {
  const file = path.join(workflowsDir, name);
  const text = fs.readFileSync(file, "utf8");
  const relative = path.relative(root, file).replaceAll(path.sep, "/");
  const triggers = topLevelTriggers(text);
  const writeAll = /^permissions:\s*write-all\s*$/m.test(text);
  const writeScopes = [...text.matchAll(/^\s{2}([A-Za-z_-]+):\s*write\s*$/gm)].map((m) => m[1]);
  const writeCapable = writeAll || writeScopes.length > 0;

  inspected.push({ workflow: relative, triggers, writeCapable, writeScopes, writeAll });

  if (writeAll) {
    failures.push(`${relative}: permissions: write-all is forbidden; grant the narrowest explicit write scope instead`);
  }

  if (writeCapable) {
    if (!triggers.includes("workflow_dispatch")) {
      failures.push(`${relative}: write-capable workflow must require workflow_dispatch`);
    }
    const automatic = triggers.filter((trigger) => trigger !== "workflow_dispatch");
    if (automatic.length) {
      failures.push(`${relative}: write-capable workflow has automatic trigger(s): ${automatic.join(", ")}`);
    }
  }
}

console.log(JSON.stringify({
  valid: failures.length === 0,
  workflows: inspected.length,
  inspected,
  failures
}, null, 2));

if (failures.length) process.exit(1);
