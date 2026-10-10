import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { runEvidenceDrill } from "../runtime/evidenceDrill.js";

const vector = "independent/vectors/shards-v1";
const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(`${vector}/share-${index}.json`, "utf8")));
const policy = JSON.parse(fs.readFileSync("independent/vectors/archive-v1/trusted-policy.json", "utf8"));
const expectedFile = "independent/vectors/drill-v1/expected.json";
const reference = `${canonicalJSONStringify(runEvidenceDrill(shares, policy))}\n`;
if (process.argv[2] === "--write") {
  fs.mkdirSync(path.dirname(expectedFile), { recursive: true });
  fs.writeFileSync(expectedFile, reference);
  process.stdout.write(`${JSON.stringify({ wrote: expectedFile })}\n`);
  process.exit(0);
}
if (process.argv.length !== 2 || !fs.existsSync(expectedFile) || fs.readFileSync(expectedFile, "utf8") !== reference) {
  throw new Error("Recovery drill vector drift; review the report before updating it");
}

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-drill-python-"));
const verifier = path.resolve("independent/python/evidence_drill.py");
const hash = (algorithm, data) => crypto.createHash(algorithm).update(data).digest("hex");

function compare(name, selected, trust, health) {
  const paths = selected.map((share, index) => {
    const file = path.join(directory, `${name}-share-${index}.json`);
    fs.writeFileSync(file, JSON.stringify(share));
    return file;
  });
  const policyPath = path.join(directory, `${name}-policy.json`);
  fs.writeFileSync(policyPath, JSON.stringify(trust));
  const result = spawnSync("python3", [verifier, ...paths, policyPath], { encoding: "utf8" });
  if (result.error) throw result.error;
  const python = JSON.parse(result.stdout);
  const javascript = runEvidenceDrill(selected, trust);
  if (canonicalJSONStringify(python) !== canonicalJSONStringify(javascript) ||
      javascript.health !== health || result.status !== (javascript.ready ? 0 : 1)) {
    throw new Error(`${name}: runtime disagreement: ${JSON.stringify({ javascript, python, stderr: result.stderr })}`);
  }
  return { name, health, passed_pairs: javascript.passed_pairs };
}

try {
  const results = [compare("ready", shares, policy, "ready")];
  const damaged = structuredClone(shares);
  damaged[0].segment_base64 = "broken";
  results.push(compare("one-damaged", damaged, policy, "degraded"));
  damaged[1].segment_base64 = "broken";
  results.push(compare("two-damaged", damaged, policy, "unrecoverable"));
  const { accepted_head, ...unbounded } = policy;
  results.push(compare("head-not-supplied", shares, unbounded, "unbounded"));
  results.push(compare("rollback", shares, { ...policy,
    accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } }, "unrecoverable"));
  results.push(compare("misidentified-slots", [shares[1], shares[0], shares[2]], policy, "unrecoverable"));
  const changed = structuredClone(shares);
  const bytes = Buffer.from(changed[1].segment_base64, "base64");
  bytes[0] ^= 1;
  changed[1].segment_base64 = bytes.toString("base64");
  changed[1].segment_sha512 = hash("sha512", bytes);
  const { root_sha3_512, ...payload } = changed[1];
  changed[1].root_sha3_512 = hash("sha3-512", canonicalJSONStringify(payload));
  results.push(compare("rehashed-damage", changed, policy, "degraded"));
  process.stdout.write(`${JSON.stringify({ protocol: "aml-drill-cross-runtime-check/1", passed: true, results }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
