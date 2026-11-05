#!/usr/bin/env node
// Opt-in local effect-observation challenge. The runner, not the adapter,
// counts loopback callback invocations. It does not prove why a call was made.
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";
import { prepareCase, checkCase } from "../conformance/action-boundary-challenge-core.js";
import { generateActionProbes } from "../conformance/action-boundary-probes.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const split = args.indexOf("--");
const options = args.slice(0, split < 0 ? undefined : split);
const selfTest = options.includes("--self-test");
const probes = options.includes("--probes");
const seedAt = options.indexOf("--probe-seed");
const seed = seedAt < 0 ? null : options[seedAt + 1];
const selectedAt = options.indexOf("--case");
const selected = selectedAt < 0 ? null : options[selectedAt + 1];
const consumed = new Set([seedAt, seedAt + 1, selectedAt, selectedAt + 1].filter(n => n >= 0));
if (options.some((item, index) => !["--self-test", "--probes"].includes(item) && !consumed.has(index)) ||
    (seedAt >= 0 && (!probes || !/^[0-9a-f]{32}$/.test(seed || ""))) ||
    (selectedAt >= 0 && (!selected || selected.startsWith("--"))) ||
    (!selfTest && (split < 0 || split === args.length - 1)) ||
    (selfTest && split >= 0)) {
  console.error("Usage: node scripts/run-action-observed-challenge.mjs [--case <id>] [--probes [--probe-seed <32 hex>]] [--self-test | -- <executable> [args...]]");
  process.exit(2);
}
const command = selfTest ? process.execPath : args[split + 1];
const commandArgs = selfTest ? [path.join(root, "pilots/action-boundary/challenge-reference-adapter.mjs")] : args.slice(split + 2);
const manifestBytes = fs.readFileSync(path.join(root, "conformance/action-boundary-challenge.json"));
const vectorBytes = fs.readFileSync(path.join(root, "pilots/action-boundary/vectors.json"));
const manifest = JSON.parse(manifestBytes);
let vectors = JSON.parse(vectorBytes);
if (manifest.protocol !== "aml-action-boundary-challenge/1" || vectors.protocol !== "aml-action-vectors/1") {
  throw new Error("Unsupported challenge data");
}
let rows = manifest.cases.filter(row => selected === null || row.id === selected);
if (selected && rows.length === 0) throw new Error(`Unknown case: ${selected}`);
const probeSeed = probes ? seed || crypto.randomBytes(16).toString("hex") : null;
if (probes) {
  const generated = generateActionProbes(manifest, vectors, probeSeed);
  rows = [...rows, ...generated.rows.filter(row => selected === null || row.input_case_id === selected)];
  vectors = generated.vectors;
}
const digest = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-observed-challenge-"));

async function observer(token, nonce) {
  const proposals = [];
  let rejected = 0;
  const server = http.createServer((request, response) => {
    if (request.method !== "POST" || request.url !== `/invoke/${nonce}` ||
        request.headers["x-aml-challenge-token"] !== token) {
      rejected++;
      response.writeHead(403).end();
      return;
    }
    let size = 0;
    const chunks = [];
    request.on("data", chunk => {
      size += chunk.length;
      if (size > 70_000) { rejected++; request.destroy(); }
      else chunks.push(chunk);
    });
    request.on("end", () => {
      if (size > 70_000) return;
      try {
        proposals.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        response.writeHead(200).end();
      } catch {
        rejected++;
        response.writeHead(400).end();
      }
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return { url: `http://127.0.0.1:${server.address().port}/invoke/${nonce}`,
    proposals, rejected: () => rejected,
    close: () => new Promise(resolve => server.close(resolve)) };
}

function invoke(command, args, file) {
  return new Promise(resolve => {
    execFile(command, [...args, file], { cwd: process.cwd(), encoding: "utf8",
      timeout: 5000, maxBuffer: 256 * 1024 }, (error, stdout) => {
      resolve({ status: error ? (typeof error.code === "number" ? error.code : 1) : 0,
        error, stdout });
    });
  });
}

const cases = [];
try {
  for (const row of rows) {
    const token = crypto.randomBytes(24).toString("hex");
    const nonce = crypto.randomBytes(16).toString("hex");
    const local = await observer(token, nonce);
    try {
      const input = prepareCase(row, vectors);
      input.host.observed_callback = { url: local.url, token };
      const file = path.join(temp, `${row.id}.json`);
      fs.writeFileSync(file, JSON.stringify(input), { flag: "wx" });
      const invocation = await invoke(command, commandArgs, file);
      let output = null;
      try { output = JSON.parse((invocation.stdout || "").trim()); } catch {}
      const failures = checkCase(row, output, invocation, vectors);
      if (!output) failures.push("single_json_stdout");
      const expected = row.expected.executed_vector ?
        vectors.cases.find(item => item.name === row.expected.executed_vector)?.proposal : null;
      if (local.proposals.length !== row.expected.tool_calls) failures.push("observed_callback_count");
      if (!isDeepStrictEqual(local.proposals, expected ? [expected] : [])) {
        failures.push("observed_proposal");
      }
      if (local.rejected() !== 0) failures.push("rejected_callback_attempts");
      cases.push({ id: row.id, passed: failures.length === 0, failures,
        observed_callback_count: local.proposals.length,
        observed_proposals: local.proposals, rejected_callback_attempts: local.rejected() });
    } finally { await local.close(); }
  }
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
const report = { protocol: "aml-action-observed-challenge-report/2",
  project_reference_self_test: selfTest, case_scope: selected ? "single" : "full",
  selected_case: selected, published_case_count: rows.filter(row => !row.id.startsWith("probe-")).length,
  probe_case_count: rows.filter(row => row.id.startsWith("probe-")).length,
  ...(probes ? { probe_seed: probeSeed } : {}),
  challenge_sha256: digest(manifestBytes), vectors_sha256: digest(vectorBytes),
  passed: cases.every(item => item.passed), cases,
  claim_boundary: "Runner-observed local callback requests and fixture response compatibility only. This cannot establish that the adapter's policy logic caused the request, authenticate a person, prove external delivery, or confer independent implementation credit without source review." };
console.log(JSON.stringify(report, null, 2));
process.exitCode = report.passed ? 0 : 1;
