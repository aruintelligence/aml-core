import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { once } from "node:events";
import { createAmlHttpServer, evaluateLockedHttpAndRender,
  signExecutionReceipt } from "../../index.js";
import { getSourceState } from "../enterprise-30min/source-state.mjs";

const args = process.argv.slice(2);
if (args.length !== 0 && (args.length !== 2 || args[0] !== "--seed" ||
    !/^[0-9a-f]{32}$/.test(args[1]))) {
  throw new TypeError("use --seed followed by 32 lowercase hexadecimal characters");
}
const seed = args.length ? args[1] : randomBytes(16).toString("hex");
const fixture = name => JSON.parse(readFileSync(new URL(`../enterprise-screen/${name}`, import.meta.url)));
const allowedIntent = fixture("intent-allowed.json");
const sensitiveIntent = fixture("intent-sensitive.json");
allowedIntent.transmission = `challenge_allowed_${seed}`;
sensitiveIntent.transmission = `challenge_sensitive_${seed}`;
const deniedContext = JSON.parse(readFileSync(new URL("../enterprise-30min/context-denied.json", import.meta.url)));
const allowedContext = JSON.parse(readFileSync(new URL("../enterprise-30min/context-allowed.json", import.meta.url)));
const token = randomBytes(32).toString("hex");
const keypair = generateKeyPairSync("ed25519");
const privateKeyPem = keypair.privateKey.export({ type: "pkcs8", format: "pem" });
const fingerprint = createHash("sha256")
  .update(keypair.publicKey.export({ type: "spki", format: "der" })).digest("hex");
const foreignKeyPem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
const sha256 = value => createHash("sha256").update(value).digest("hex");
const injectedHtml = `<h2>Unreviewed replacement ${seed}</h2>`;

async function start(profile, context) {
  const server = createAmlHttpServer({ request_auth: { bearer_token: token },
    locked_policy: { profile, context, mode: "enforce", failure_mode: "closed" },
    receipt_signing: { private_key_pem: privateKeyPem, signer: "adversarial-local-pilot" } });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { server, url: `http://127.0.0.1:${server.address().port}/v1/deployment/evaluate` };
}

const cases = [
  { id: "valid_allow", intent: allowedIntent, status: "rendered", reason: "verified_allow", naive: 1, verified: 1 },
  { id: "valid_suppression", intent: sensitiveIntent, status: "blocked", reason: "policy_suppressed", naive: 0, verified: 0 },
  { id: "outer_html_swap", intent: allowedIntent, status: "rendered", reason: "verified_allow", naive: 1, verified: 1 },
  { id: "receipt_html_swap", intent: allowedIntent, status: "blocked", reason: "receipt_invalid", naive: 1, verified: 0 },
  { id: "unsigned_receipt", intent: allowedIntent, status: "blocked", reason: "receipt_invalid", naive: 1, verified: 0 },
  { id: "foreign_signer", intent: allowedIntent, status: "blocked", reason: "receipt_untrusted", naive: 1, verified: 0 },
  { id: "replayed_nonce", intent: allowedIntent, status: "blocked", reason: "receipt_binding_mismatch", naive: 1, verified: 0 },
  { id: "substituted_intent", intent: sensitiveIntent, status: "blocked", reason: "receipt_binding_mismatch", naive: 1, verified: 0 },
  { id: "different_context", intent: sensitiveIntent, status: "blocked", reason: "receipt_binding_mismatch", naive: 1, verified: 0 },
  { id: "different_profile", intent: allowedIntent, status: "blocked", reason: "receipt_binding_mismatch", naive: 1, verified: 0 },
  { id: "flipped_decision", intent: sensitiveIntent, status: "blocked", reason: "decision_mismatch", naive: 1, verified: 0 },
  { id: "shadow_override", intent: sensitiveIntent, status: "blocked", reason: "unexpected_deployment_policy", naive: 1, verified: 0 },
  { id: "untrusted_policy_source", intent: allowedIntent, status: "blocked", reason: "unexpected_deployment_policy", naive: 1, verified: 0 },
  { id: "duplicate_outer_key", intent: allowedIntent, status: "blocked", reason: "ambiguous_json", naive: 1, verified: 0 },
  { id: "escaped_duplicate_outer_key", intent: allowedIntent, status: "blocked", reason: "ambiguous_json", naive: 1, verified: 0 },
  { id: "duplicate_receipt_key", intent: allowedIntent, status: "blocked", reason: "ambiguous_json", naive: 1, verified: 0 },
  { id: "response_too_large", intent: allowedIntent, status: "blocked", reason: "response_too_large", naive: 1, verified: 0 }
];

const services = [];
try {
  const primary = await start("human_first", deniedContext); services.push(primary);
  const consented = await start("human_first", allowedContext); services.push(consented);
  const otherProfile = await start("calm_default", deniedContext); services.push(otherProfile);
  const cachedNonce = randomBytes(32).toString("hex");
  const cachedResponse = await fetch(primary.url, { method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ intent: allowedIntent, request_nonce: cachedNonce }) });
  assert.equal(cachedResponse.status, 200);
  const cachedBody = await cachedResponse.json();
  const results = [];

  for (const item of cases) {
    let wire;
    let originalHtml;
    const verifiedHtml = [];
    const outcome = await evaluateLockedHttpAndRender({ url: primary.url, token,
      intent: item.intent, profile: "human_first", context: deniedContext,
      trustedReceiptFingerprints: [fingerprint],
      ...(item.id === "response_too_large" ? { maxResponseBytes: 128 } : {}),
      render: html => { verifiedHtml.push(html); },
      fetchImpl: async (url, init) => {
        const { request_nonce } = JSON.parse(init.body);
        let response;
        if (item.id === "replayed_nonce") {
          assert.notEqual(request_nonce, cachedNonce);
          wire = structuredClone(cachedBody);
          originalHtml = wire.receipt.selected_render.html;
          return new Response(JSON.stringify(wire), { status: 200 });
        }
        if (item.id === "substituted_intent") {
          response = await fetch(url, { ...init,
            body: JSON.stringify({ intent: allowedIntent, request_nonce }) });
        } else {
          const destination = item.id === "different_context" ? consented.url :
            item.id === "different_profile" ? otherProfile.url : url;
          response = await fetch(destination, init);
        }
        assert.equal(response.status, 200);
        wire = await response.json();
        originalHtml = wire.receipt.selected_render.html;
        switch (item.id) {
          case "outer_html_swap":
            wire.selected_render.html = injectedHtml;
            break;
          case "receipt_html_swap":
            wire.receipt.selected_render.html = injectedHtml;
            wire.selected_render.html = injectedHtml;
            break;
          case "unsigned_receipt":
            delete wire.receipt.signature;
            break;
          case "foreign_signer": {
            const { signature, ...unsigned } = wire.receipt;
            wire.receipt = signExecutionReceipt(unsigned, foreignKeyPem, { signer: "foreign-test-key" });
            break;
          }
          case "flipped_decision":
          case "shadow_override":
            wire.effective_allowed = true;
            wire.aml_allowed = true;
            wire.would_suppress = false;
            wire.selected_render.html = injectedHtml;
            if (item.id === "shadow_override") wire.mode = "shadow";
            break;
          case "untrusted_policy_source":
            wire.policy_source = "request_or_default";
            break;
        }
        let responseText = JSON.stringify(wire);
        if (item.id === "duplicate_outer_key") {
          responseText = responseText.replace('"effective_allowed":true',
            '"effective_allowed":false,"effective_allowed":true');
        } else if (item.id === "escaped_duplicate_outer_key") {
          responseText = responseText.replace('"effective_allowed":true',
            String.raw`"effective_allowed":false,"effective_\u0061llowed":true`);
        } else if (item.id === "duplicate_receipt_key") {
          responseText = responseText.replace('"receipt":{"protocol":',
            '"receipt":{"protocol":"forged","protocol":');
        }
        if (item.id.startsWith("duplicate_") || item.id === "escaped_duplicate_outer_key") {
          assert.notEqual(responseText, JSON.stringify(wire));
          // The deliberately unsafe host applies the usual last-key-wins parse.
          wire = JSON.parse(responseText);
        }
        return new Response(responseText, { status: 200 });
      }
    });
    // An intentionally unsafe comparison host trusts the unsigned outer
    // envelope's boolean and HTML. It is not an alternative AML implementation.
    const naiveHtml = wire?.effective_allowed && typeof wire.selected_render?.html === "string"
      ? [wire.selected_render.html] : [];
    const verifiedHash = verifiedHtml.length ? sha256(verifiedHtml[0]) : null;
    const naiveHash = naiveHtml.length ? sha256(naiveHtml[0]) : null;
    const originalHash = originalHtml ? sha256(originalHtml) : null;
    const passed = outcome.status === item.status && outcome.reason === item.reason &&
      verifiedHtml.length === item.verified && naiveHtml.length === item.naive &&
      (item.id !== "outer_html_swap" ||
        (verifiedHash === originalHash && naiveHash !== originalHash)) &&
      (item.id !== "valid_allow" || verifiedHash === originalHash);
    results.push({ id: item.id, passed, naive_callback_entries: naiveHtml.length,
      verified_callback_entries: verifiedHtml.length, verified_status: outcome.status,
      verified_reason: outcome.reason, response_receipt_sha256: outcome.receipt_sha256,
      original_html_sha256: originalHash, naive_html_sha256: naiveHash,
      verified_html_sha256: verifiedHash });
  }

  const passed = results.every(result => result.passed);
  process.stdout.write(`${JSON.stringify({ protocol: "aml-signed-gate-adversarial/1",
    provenance: "project-authored localhost comparison with a deliberately unsafe host",
    ...getSourceState(), seed, passed, case_count: results.length, cases: results,
    claim_boundary: "Checks callback entry and bytes for these cases only. It does not prove browser paint, truthful declarations, organizational signer identity, production security, or independent validation." }, null, 2)}\n`);
  if (!passed) process.exitCode = 1;
} finally {
  await Promise.all(services.map(({ server }) => new Promise((done, reject) =>
    server.close(error => error ? reject(error) : done()))));
}
