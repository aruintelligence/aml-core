import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(process.cwd());
const required = [
  "protocol/discovery.json",
  "protocol/wireProtocol.js",
  "runtime/capabilityNegotiation.js",
  "runtime/policyPassport.js",
  "runtime/contentAddressedBundle.js",
  "runtime/selectiveDisclosure.js",
  "runtime/federatedExchange.js",
  "runtime/causalExecutionGraph.js",
  "schema/policy-passport.schema.json",
  "schema/wire-envelope.schema.json",
  "rfcs/0005-cross-system-interoperability.md",
  "rfcs/0006-causal-execution-graphs.md",
  "docs/INTEROPERABILITY_STANDARD.md"
];

test("interoperability standard surface remains present", () => {
  for (const relative of required) {
    assert.equal(fs.existsSync(path.join(root, relative)), true, `missing ${relative}`);
  }
});

test("protocol discovery advertises implemented interoperability primitives", () => {
  const discovery = JSON.parse(fs.readFileSync(path.join(root, "protocol/discovery.json"), "utf8"));
  assert.equal(discovery.protocol, "aml-discovery/1");
  for (const capability of [
    "policy-passports",
    "selective-disclosure",
    "content-addressed-bundles",
    "causal-execution-graphs",
    "execution-receipts"
  ]) {
    assert.equal(discovery.capabilities.includes(capability), true, `missing capability ${capability}`);
  }
});
