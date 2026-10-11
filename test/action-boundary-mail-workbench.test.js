import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { webcrypto } from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { mailTargetBytes } from "../pilots/action-boundary/mail-target-core.mjs";
import { mailTargetResource } from "../pilots/action-boundary/mail-target-manifest.mjs";

const source = fs.readFileSync(new URL("../pilots/action-boundary/mail-target-core.mjs", import.meta.url));
const browser = fs.readFileSync(new URL("../docs/mail-target-core.mjs", import.meta.url));

test("browser and Node use identical schema bytes and digests", async () => {
  assert.deepEqual(browser, source);
  const valid = [
    { to: "team@example.test" },
    { to: ["team@example.test", "editor@example.test"], cc: "one@example.test", bcc: ["archive@example.test"] },
    { to: "team@example.test", cc: [], bcc: [], subject: "Release", body: "Ready." },
    { to: "team@example.test", bcc: ["outside@example.test"] },
    { to: "é@example.test", bcc: ["duplicate@example.test", "duplicate@example.test"] }
  ];
  for (const args of valid) {
    const { manifest, bytes } = mailTargetBytes(args);
    assert.equal(bytes, canonicalJSONStringify(manifest));
    const digest = Buffer.from(await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(bytes))).toString("hex");
    assert.equal(mailTargetResource(args).resource, `mail-targets-sha256:${digest}`);
    assert.equal(crypto.createHash("sha256").update(bytes, "utf8").digest("hex"), digest);
  }
});

test("workbench schema rejects unsupported destinations and malformed fields", () => {
  for (const args of [
    { to: "team@example.test", recipients: ["outside@example.test"] },
    { to: "team@example.test", bcc: null },
    { to: "team@example.test", cc: [""] },
    { to: "team@example.test", bcc: [" bad@example.test"] },
    { to: [] }, { to: "team@example.test", subject: 3 }
  ]) assert.throws(() => mailTargetBytes(args));
});

test("recipient-only scope distinguishes BCC but does not bind body", () => {
  const intended = { to: "team@example.test", body: "Ready." };
  assert.notEqual(mailTargetResource(intended).resource,
    mailTargetResource({ ...intended, bcc: ["outside@example.test"] }).resource);
  assert.equal(mailTargetResource(intended).resource,
    mailTargetResource({ ...intended, body: "Changed text." }).resource);
});
