#!/usr/bin/env node
// CI negative controls for `aml verify` (Directive 010). Given the directory a
// job just compiled and the manifest digest it pinned at build time, prove
// the pinned decision is a real decision: the pinned bundle authorizes
// (exit 0), while an unpinned, wrongly pinned, diagnostic or tampered bundle
// does not. Works on a temporary copy; the built bundle is never modified.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../bin/aml.js", import.meta.url));
const [directory, pin] = process.argv.slice(2);
if (!directory || !/^[0-9a-f]{64}$/.test(pin ?? "")) {
  console.error("usage: node scripts/check-ci-bundle-pin.mjs <compiled-dir> <manifest-sha256>");
  process.exit(2);
}
const verify = (manifest, ...extra) => {
  const r = spawnSync(process.execPath, [cli, "verify", manifest, ...extra], { encoding: "utf8" });
  return { status: r.status, authorized: /^Authorized: true$/m.test(r.stdout), out: r.stdout + r.stderr };
};
const work = fs.mkdtempSync(path.join(os.tmpdir(), "aml-ci-bundle-pin-"));
const failures = [];
const expect = (name, got, status, authorized) => {
  if (got.status !== status || got.authorized !== authorized) failures.push(`${name}: exit ${got.status}, authorized ${got.authorized}\n${got.out}`);
};
try {
  const copy = path.join(work, "dist");
  fs.cpSync(directory, copy, { recursive: true });
  const manifest = path.join(copy, "build_manifest.json");
  expect("pinned", verify(manifest, "--expected-sha256", pin), 0, true);
  expect("unpinned", verify(manifest), 3, false);
  expect("wrong pin", verify(manifest, "--expected-sha256", "0".repeat(64)), 3, false);
  expect("non-canonical pin", verify(manifest, "--expected-sha256", pin.toUpperCase()), 3, false);
  const diagnostic = verify(manifest, "--diagnostic-only");
  expect("diagnostic", diagnostic, 0, false);
  if (!/NOT AN AUTHORIZATION DECISION/.test(diagnostic.out)) failures.push("diagnostic output lacks NOT AN AUTHORIZATION DECISION");
  // An artifact changed after the build: integrity fails even with the right pin.
  fs.appendFileSync(path.join(copy, "index.html"), "<!-- tampered -->");
  expect("tampered artifact", verify(manifest, "--expected-sha256", pin), 1, false);
  // A rewritten manifest that matches the tampered artifact: consistent, but no longer the pinned digest.
  const m = JSON.parse(fs.readFileSync(manifest, "utf8"));
  const html = fs.readFileSync(path.join(copy, "index.html"));
  m.artifacts["index.html"] = { ...m.artifacts["index.html"],
    sha256: (await import("node:crypto")).createHash("sha256").update(html).digest("hex"), bytes: html.length };
  fs.writeFileSync(manifest, JSON.stringify(m, null, 2));
  expect("re-sealed manifest", verify(manifest, "--expected-sha256", pin), 3, false);
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
console.log(JSON.stringify({ protocol: "aml-ci-bundle-pin/1", cases: 7, failures }, null, 2));
process.exit(failures.length ? 1 : 0);
