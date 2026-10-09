#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  createWireEnvelope, validateWireEnvelope, negotiateWireSession,
  createPolicyPassport, verifyPolicyPassport,
  createContentAddressedBundle, verifyContentAddressedBundle,
  createDisclosureCommitment, discloseClaims, verifyDisclosureProof,
  createCausalEvent, createCausalExecutionGraph, verifyCausalExecutionGraph
} from "../index.js";

const runtime = path.resolve("independent/python/wire_runtime.py");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-wire-python-"));
const clone = (value) => structuredClone(value);

function file(name, value) {
  const output = path.join(temp, `${name}.json`);
  fs.writeFileSync(output, `${JSON.stringify(value, null, 2)}\n`);
  return output;
}

function run(args, expected) {
  const result = spawnSync("python3", [runtime, ...args], { encoding: "utf8" });
  assert.equal(result.status, expected ? 0 : 1, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.valid ?? report.accepted, expected, JSON.stringify(report));
  return report;
}

function verify(kind, name, value, expected, extra = []) {
  return run(["verify", kind, file(name, value), ...extra], expected);
}

try {
  const discovery = JSON.parse(fs.readFileSync("protocol/discovery.json", "utf8"));
  const remote = {
    versions: ["0.9", "1.0"],
    capabilities: ["content-addressed-bundles", "policy-passports", "selective-disclosure", "causal-execution-graphs"]
  };
  const required = ["policy-passports", "content-addressed-bundles"];
  const referenceSession = negotiateWireSession({ versions: discovery.wire_versions, capabilities: discovery.capabilities }, remote, required);
  const session = run(["negotiate", "protocol/discovery.json", file("remote", remote), ...required.flatMap(value => ["--required", value])], true);
  assert.deepEqual(session, referenceSession);
  run(["negotiate", "protocol/discovery.json", file("remote", remote), "--required", "unavailable-capability"], false);

  const envelope = createWireEnvelope({
    kind: "policy-passport", payload: { profile: "calm_default" },
    capabilities: required, issued_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-02T00:00:00Z"
  });
  assert.equal(validateWireEnvelope(envelope, { now: "2030-01-01T12:00:00Z" }).valid, true);
  verify("envelope", "envelope", envelope, true, ["--now", "2030-01-01T12:00:00Z", "--allowed-kind", "policy-passport"]);
  const badEnvelope = { ...envelope, protocol: "aml-wire/0" };
  assert.equal(validateWireEnvelope(badEnvelope).valid, false);
  verify("envelope", "bad-envelope", badEnvelope, false);
  verify("envelope", "expired-envelope", envelope, false, ["--now", "2030-01-02T00:00:00Z"]);

  const passport = createPolicyPassport({
    subject: "example", profile: "calm_default", preferences: { reduced_motion: true, attention_budget: 3 },
    issued_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-02T00:00:00Z"
  });
  assert.equal(verifyPolicyPassport(passport, { now: "2030-01-01T12:00:00Z" }).valid, true);
  verify("passport", "passport", passport, true, ["--now", "2030-01-01T12:00:00Z"]);
  const badPassport = { ...passport, preferences: { ...passport.preferences, attention_budget: 999 } };
  assert.equal(verifyPolicyPassport(badPassport, { now: "2030-01-01T12:00:00Z" }).valid, false);
  verify("passport", "bad-passport", badPassport, false, ["--now", "2030-01-01T12:00:00Z"]);
  verify("passport", "expired-passport", passport, false, ["--now", "2030-01-02T00:00:00Z"]);

  const bundle = createContentAddressedBundle({ "policy.json": { profile: "calm_default", version: 1 }, "note.txt": "hello" });
  assert.equal(verifyContentAddressedBundle(bundle).valid, true);
  verify("bundle", "bundle", bundle, true);
  const badBundle = clone(bundle);
  badBundle.files["note.txt"].value = "changed";
  assert.equal(verifyContentAddressedBundle(badBundle).valid, false);
  verify("bundle", "bad-bundle", badBundle, false);

  const disclosure = discloseClaims(createDisclosureCommitment({ region: "west", tier: "pro" }), ["region"]);
  assert.equal(verifyDisclosureProof(disclosure).valid, true);
  verify("disclosure", "disclosure", disclosure, true);
  const badDisclosure = clone(disclosure);
  badDisclosure.disclosed[0].value = "east";
  assert.equal(verifyDisclosureProof(badDisclosure).valid, false);
  verify("disclosure", "bad-disclosure", badDisclosure, false);

  const received = createCausalEvent({ kind: "received", payload: { request: 1 } });
  const evaluated = createCausalEvent({ kind: "evaluated", payload: { allowed: true }, parents: [received.event_hash] });
  const graph = createCausalExecutionGraph([received, evaluated]);
  assert.equal(verifyCausalExecutionGraph(graph).valid, true);
  verify("graph", "graph", graph, true);
  const badGraph = clone(graph);
  badGraph.events[evaluated.event_hash].payload.allowed = false;
  assert.equal(verifyCausalExecutionGraph(badGraph).valid, false);
  verify("graph", "bad-graph", badGraph, false);
  const orphan = createCausalEvent({ kind: "orphan", parents: ["f".repeat(64)] });
  const orphanGraph = createCausalExecutionGraph([orphan]);
  assert.equal(verifyCausalExecutionGraph(orphanGraph).valid, false);
  assert.equal(verify("graph", "orphan-graph", orphanGraph, false).reason, "missing_parent");

  console.log("Python wire runtime: negotiation, five artifact classes, and tamper cases passed");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
