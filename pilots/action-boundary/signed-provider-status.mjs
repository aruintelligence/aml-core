#!/usr/bin/env node
// Controlled provider-side status signer. The signer and DB share a local
// identity in this fixture; production deployments need real key separation.
import crypto from "node:crypto";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const [database, privateKeyFile] = process.argv.slice(2);
const provider = fileURLToPath(new URL("./sqlite-provider-fixture.py", import.meta.url));
const DOMAIN = Buffer.from("AML-LOCAL-PROVIDER-STATUS/1\0", "utf8");
if (!database?.startsWith("/") || !privateKeyFile?.startsWith("/")) {
  throw Error("absolute_provider_paths_required");
}
const operationId = fs.readFileSync(0, "utf8").trim();
if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(operationId)) {
  throw Error("invalid_operation_id");
}
const child = spawnSync("python3", [provider, database, "status"],
  { input: operationId, encoding: "utf8", timeout: 20_000 });
if (child.error || child.status !== 0) throw child.error || Error("provider_status_unavailable");
const record = JSON.parse(child.stdout).record;
const statement = { protocol: "aml-fixture-provider-status/1", issuer: "fixture-provider",
  operation_id: operationId, record };
const bytes = Buffer.concat([DOMAIN, Buffer.from(canonicalJSONStringify(statement), "utf8")]);
const key = crypto.createPrivateKey(fs.readFileSync(privateKeyFile));
if (key.asymmetricKeyType !== "ed25519") throw Error("ed25519_key_required");
const signature = crypto.sign(null, bytes, key).toString("base64");
console.log(canonicalJSONStringify({ ...statement, signature }));
