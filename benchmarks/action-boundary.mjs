#!/usr/bin/env node
// Local microbenchmark; no external provider and no security checks disabled.
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { dispatchAction, planAction } from "../pilots/action-boundary/boundary.mjs";
import { createLocalOneShotGrants } from "../pilots/action-boundary/one-shot-grants.mjs";
import { createFileOneShotGrants } from "../pilots/action-boundary/file-one-shot-grants.mjs";

const proposal = { protocol: "aml-proposed-action/1", tool: "local.append", effect: "write",
  resource: "sandbox:outbox", purpose: "Local performance fixture",
  arguments: { body: "x".repeat(256), destination: "sandbox:outbox" } };
const allow = { protocol: "aml-action-policy/1", rules: [
  { tool: proposal.tool, effect: proposal.effect, resource: proposal.resource, requires_approval: false }
] };
const requireApproval = { ...allow, rules: [{ ...allow.rules[0], requires_approval: true }] };
const callback = async () => true;
const bytes = canonicalJSONStringify(proposal);
const digest = planAction(proposal, requireApproval).proposal_sha256;
const iterations = Number(process.env.AML_ACTION_BENCH_ITERATIONS || 500);
if (!Number.isSafeInteger(iterations) || iterations < 20 || iterations > 10000) {
  throw new Error("AML_ACTION_BENCH_ITERATIONS must be 20..10000");
}
const rows = [];
async function bench(name, count, fn) {
  const samples = [];
  for (let i = 0; i < Math.min(50, count); i++) await fn(i); // Warm-up.
  const rssBefore = process.memoryUsage().rss;
  const started = performance.now();
  for (let i = 0; i < count; i++) {
    const a = performance.now();
    await fn(i);
    samples.push(performance.now() - a);
  }
  const elapsed = performance.now() - started;
  samples.sort((a, b) => a - b);
  rows.push({ name, iterations: count,
    median_ms: Number(samples[Math.floor((count - 1) * .5)].toFixed(4)),
    p95_ms: Number(samples[Math.floor((count - 1) * .95)].toFixed(4)),
    throughput_ops_s: Number((count / (elapsed / 1000)).toFixed(1)),
    rss_before_bytes: rssBefore, rss_after_bytes: process.memoryUsage().rss });
}

await bench("canonicalize", iterations, () => canonicalJSONStringify(proposal));
await bench("sha256_canonical_bytes", iterations, () => crypto.createHash("sha256").update(bytes).digest("hex"));
await bench("plan_policy_and_digest", iterations, () => planAction(proposal, allow));
await bench("unprotected_same_callback", iterations, callback);
await bench("guarded_no_approval_callback", iterations, () =>
  dispatchAction(proposal, { policy: allow, executeTool: callback }));
const local = createLocalOneShotGrants();
await bench("guarded_local_one_use_approval", iterations, () => {
  const approval = local.issue(digest);
  return dispatchAction(proposal, { policy: requireApproval,
    requestApproval: async () => approval, consumeApproval: local.consume,
    executeTool: callback });
});
const temp = await fs.mkdtemp(path.join(os.tmpdir(), "aml-bench-grants-"));
try {
  const file = createFileOneShotGrants({ directory: temp });
  await bench("file_grant_issue_consume", 20, async () => {
    const approval = await file.issue(digest);
    if (!await file.consume({ approval, proposal_sha256: digest })) throw Error("file_claim_failed");
  });
} finally { await fs.rm(temp, { recursive: true, force: true }); }
const startConcurrent = performance.now();
await Promise.all(Array.from({ length: 100 }, () =>
  dispatchAction(proposal, { policy: allow, executeTool: callback })));
const concurrentMs = performance.now() - startConcurrent;
console.log(JSON.stringify({ schema: "aml-action-benchmark/1", commit: spawnSync("git", ["rev-parse", "HEAD"],
  { encoding: "utf8" }).stdout.trim(), worktree_note: "branch may contain uncommitted changes",
  platform: `${process.platform}/${process.arch}`, node: process.version,
  fixture_utf8_bytes: Buffer.byteLength(bytes), iterations, warmup_per_case: Math.min(50, iterations),
  rows, concurrent: { requests: 100, elapsed_ms: Number(concurrentMs.toFixed(4)),
    throughput_ops_s: Number((100 / (concurrentMs / 1000)).toFixed(1)) },
  interpretation: "Local sequential microbenchmark, no provider I/O. RSS is process-wide and noisy. Callback return is not delivery." }, null, 2));
