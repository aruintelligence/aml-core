import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const html = fs.readFileSync(new URL("../docs/resilience-lab.html", import.meta.url), "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, "inline simulation must be present");
const context = vm.createContext({});
vm.runInContext(script, context, { timeout: 1000 });
const simulate = context.simulatePlacementTopology;
const parseManifest = context.parsePlacementManifest;
const analyzeChanges = context.analyzePlacementChanges;
const separated = [0, 1, 2].map(index => ({ index, site: `site-${index}`,
  infrastructure: `system-${index}`, custodian: `keeper-${index}` }));

test("the page rehearses every distinct declared domain", () => {
  const report = simulate(separated);
  assert.equal(report.ready, true);
  assert.equal(report.scenarios.length, 9);
  assert.equal(report.scenarios.filter(scenario => !scenario.recoveryPossible).length, 0);
});

test("a shared site or custodian reveals a lost recovery path", () => {
  const shared = structuredClone(separated);
  shared[1].site = shared[0].site;
  shared[2].custodian = shared[0].custodian;
  const report = simulate(shared);
  assert.equal(report.ready, false);
  assert.deepEqual(Array.from(report.scenarios.filter(scenario => !scenario.recoveryPossible), item => item.dimension),
    ["site", "custodian"]);
});

test("empty labels cannot pass and the UI states its verification boundary", () => {
  assert.equal(simulate([{ ...separated[0], site: "" }, separated[1], separated[2]]).valid, false);
  assert.match(html, /It does not read or upload your evidence/);
  assert.match(html, /The lab alone cannot mark storage ready/);
  assert.doesNotMatch(html, /<script[^>]+src=/);
});

test("a downloaded manifest can be reopened with the same declared failure cases", () => {
  const shared = structuredClone(separated);
  shared[1].site = shared[0].site;
  const opened = parseManifest(JSON.stringify({ protocol: "aml-evidence-placement/1", shares: shared }));
  assert.deepEqual(JSON.parse(JSON.stringify(opened)), shared);
  assert.deepEqual(JSON.parse(JSON.stringify(simulate(opened))), JSON.parse(JSON.stringify(simulate(shared))));
  assert.match(html, /Open manifest/);
  assert.match(html, /Select a failure to see its impact/);
});

test("manifest import rejects malformed, oversized, or incomplete declarations", () => {
  const manifest = { protocol: "aml-evidence-placement/1", shares: separated };
  assert.throws(() => parseManifest("not json"), /valid JSON/);
  assert.throws(() => parseManifest(" ".repeat(65537)), /too large/);
  assert.throws(() => parseManifest(JSON.stringify({ ...manifest, protocol: "other" })), /Expected/);
  assert.throws(() => parseManifest(JSON.stringify({ ...manifest, shares: [separated[0], separated[0], separated[2]] })), /indexed/);
  assert.throws(() => parseManifest(JSON.stringify({ ...manifest, shares: [{ ...separated[0], site: " " }, separated[1], separated[2]] })), /nonempty/);
  assert.throws(() => parseManifest(JSON.stringify({ ...manifest, shares: [{ ...separated[0], site: "x".repeat(129) }, separated[1], separated[2]] })), /128/);
});

test("dependency review identifies the minimum label changes for separate single-domain survival", () => {
  assert.equal(analyzeChanges(separated).minimumLabelChanges, 0);
  const shared = structuredClone(separated);
  shared[1].site = shared[0].site;
  shared[2].custodian = shared[0].custodian;
  const result = analyzeChanges(shared);
  assert.equal(result.minimumLabelChanges, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(result.conflicts)), [
    { dimension: "site", value: "site-0", shares: [0, 1], keep: 0, separate: [1] },
    { dimension: "custodian", value: "keeper-0", shares: [0, 2], keep: 0, separate: [2] }
  ]);
  assert.match(html, /A label edit alone does not repair storage/);
});

test("three shares in one domain require two independent assignments", () => {
  const shared = structuredClone(separated);
  shared[1].infrastructure = shared[0].infrastructure;
  shared[2].infrastructure = shared[0].infrastructure;
  const result = analyzeChanges(shared);
  assert.equal(result.minimumLabelChanges, 2);
  assert.deepEqual(Array.from(result.conflicts[0].separate), [1, 2]);
  assert.equal(analyzeChanges([{ ...separated[0], site: "" }, separated[1], separated[2]]).valid, false);
});
