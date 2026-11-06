#!/usr/bin/env node
// Controlled provider-side status signer. The signer and DB share a local
// identity in this fixture; production deployments need real key separation.
import crypto from "node:crypto";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const [database, privateKeyFile, challenge] = process.argv.slice(2);
const provider = fileURLToPath(new URL("./sqlite-provider-fixture.py", import.meta.url));
const version = challenge === undefined ? 1 : 2;
const DOMAIN = Buffer.from(`AML-LOCAL-PROVIDER-STATUS/${version}\0`, "utf8");
if (!database?.startsWith("/") || !privateKeyFile?.startsWith("/")) {
  throw Error("absolute_provider_paths_required");
}
const operationId = fs.readFileSync(0, "utf8").trim();
if (version === 2 && !/^[0-9a-f]{64}$/.test(challenge)) throw Error("invalid_challenge");
if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(operationId)) {
  throw Error("invalid_operation_id");
}
const child = spawnSync("python3", [provider, database, "status"],
  { input: operationId, encoding: "utf8", timeout: 20_000 });
if (child.error || child.status !== 0) throw child.error || Error("provider_status_unavailable");
const record = JSON.parse(child.stdout).record;
const statement = { protocol: `aml-fixture-provider-status/${version}`, issuer: "fixture-provider",
  operation_id: operationId, ...(version === 2 ? { challenge } : {}), record };
const bytes = Buffer.concat([DOMAIN, Buffer.from(canonicalJSONStringify(statement), "utf8")]);
const key = crypto.createPrivateKey(fs.readFileSync(privateKeyFile));
if (key.asymmetricKeyType !== "ed25519") throw Error("ed25519_key_required");
const signature = crypto.sign(null, bytes, key).toString("base64");
console.log(canonicalJSONStringify({ ...statement, signature }));
