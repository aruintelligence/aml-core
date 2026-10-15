import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadScenarioFiles, startScreenPilot } from "../pilots/enterprise-screen/server.mjs";

test("localhost screen host only releases signed and allowed HTML; outages leave no HTML", async () => {
  const pilot = await startScreenPilot({ port: 0 });
  const post = async body => {
    const response = await fetch(`${pilot.url}/api/evaluate`, { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  try {
    const page = await fetch(pilot.url);
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);
    assert.match(html, /<iframe[^>]*sandbox(?:\s|>)/);
    assert.doesNotMatch(html, /Bearer |BEGIN PRIVATE KEY/);

    const allowed = await post({ fixture: "allowed" });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.body.decision, "allow");
    assert.equal(allowed.body.reason, "verified_allow");
    assert.match(allowed.body.html, /<h2>Review the plan before you choose\.<\/h2>/);
    assert.match(allowed.body.receipt_sha256, /^[0-9a-f]{64}$/);
    assert.doesNotMatch(JSON.stringify(allowed.body), /BEGIN PRIVATE KEY|Bearer /);

    const sensitive = await post({ fixture: "sensitive" });
    assert.deepEqual([sensitive.status, sensitive.body.decision, sensitive.body.reason],
      [200, "blocked", "policy_suppressed"]);
    assert.equal(Object.hasOwn(sensitive.body, "html"), false);
    assert.match(sensitive.body.receipt_sha256, /^[0-9a-f]{64}$/);

    const override = await post({ fixture: "sensitive", context: { consent_granted: true } });
    assert.deepEqual([override.status, override.body.error], [400, "unknown_fixture"]);
    const unknown = await post({ fixture: "other" });
    assert.deepEqual([unknown.status, unknown.body.error], [400, "unknown_fixture"]);
    const direct = await fetch(`${pilot.url}/v1/deployment/evaluate`, { method: "POST" });
    assert.equal(direct.status, 404);

    await new Promise((done, reject) => pilot.amlServer.close(error => error ? reject(error) : done()));
    const outage = await post({ fixture: "allowed" });
    assert.deepEqual([outage.status, outage.body.decision, outage.body.reason],
      [200, "blocked", "transport_or_response_error"]);
    assert.equal(Object.hasOwn(outage.body, "html"), false);
  } finally {
    await pilot.close();
  }
});

test("host-supplied scenario files are bounded and snapshotted before the browser selects a proposal", async () => {
  const directory = mkdtempSync(join(tmpdir(), "aml-screen-scenario-"));
  const intentPath = join(directory, "intent.json");
  const contextPath = join(directory, "context.json");
  const source = name => readFileSync(new URL(`../pilots/enterprise-30min/${name}`, import.meta.url), "utf8");
  writeFileSync(intentPath, readFileSync(new URL("../pilots/enterprise-screen/intent-sensitive.json", import.meta.url)));
  writeFileSync(contextPath, source("context-denied.json"));
  try {
    assert.throws(() => loadScenarioFiles(intentPath, ""), /both --intent and --context/);
    const pilot = await startScreenPilot({ port: 0,
      scenario: loadScenarioFiles(intentPath, contextPath) });
    try {
      const info = await (await fetch(`${pilot.url}/api/info`)).json();
      assert.deepEqual(info, { mode: "custom" });
      const page = await (await fetch(pilot.url)).text();
      assert.doesNotMatch(page, /Personalize your plan using your data\?/);

      // Editing files after startup cannot grant consent to this running host.
      writeFileSync(contextPath, source("context-allowed.json"));
      const post = async fixture => {
        const response = await fetch(`${pilot.url}/api/evaluate`, { method: "POST",
          headers: { "content-type": "application/json" }, body: JSON.stringify({ fixture }) });
        return { status: response.status, body: await response.json() };
      };
      const denied = await post("custom");
      assert.deepEqual([denied.body.decision, denied.body.reason, Object.hasOwn(denied.body, "html")],
        ["blocked", "policy_suppressed", false]);
      assert.equal((await post("allowed")).status, 400);
      const override = await fetch(`${pilot.url}/api/evaluate`, { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ fixture: "custom", context: { consent_granted: true } }) });
      assert.equal(override.status, 400);
    } finally { await pilot.close(); }

    const granted = await startScreenPilot({ port: 0,
      scenario: loadScenarioFiles(intentPath, contextPath) });
    try {
      const response = await fetch(`${granted.url}/api/evaluate`, { method: "POST",
        headers: { "content-type": "application/json" }, body: '{"fixture":"custom"}' });
      const body = await response.json();
      assert.equal(body.decision, "allow");
      assert.match(body.html, /Personalize your plan using your data\?/);
    } finally { await granted.close(); }

    writeFileSync(intentPath, "x".repeat(64 * 1024 + 1));
    assert.throws(() => loadScenarioFiles(intentPath, contextPath), /file too large/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
