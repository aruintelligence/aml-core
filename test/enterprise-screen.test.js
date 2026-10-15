import test from "node:test";
import assert from "node:assert/strict";
import { startScreenPilot } from "../pilots/enterprise-screen/server.mjs";

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
