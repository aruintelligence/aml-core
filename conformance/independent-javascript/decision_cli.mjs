#!/usr/bin/env node

let raw = "";
for await (const chunk of process.stdin) raw += chunk;

function fail(message) {
  process.stdout.write(JSON.stringify({ error: message }));
  process.exit(1);
}

let payload;
try {
  payload = JSON.parse(raw);
} catch {
  fail("invalid JSON input");
}

if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
  fail("input must be a JSON object");
}
if (!("attention_cost" in payload) || !("restoration_value" in payload)) {
  fail("missing required score");
}

const attention = payload.attention_cost;
const restoration = payload.restoration_value;
if (typeof attention !== "number" || typeof restoration !== "number") {
  fail("scores must be JSON numbers");
}
if (!Number.isFinite(attention) || !Number.isFinite(restoration)) {
  fail("scores must be finite");
}

const decision = restoration >= attention ? "ALLOW" : "SUPPRESS";
process.stdout.write(JSON.stringify({ decision }));
