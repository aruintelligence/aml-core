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
