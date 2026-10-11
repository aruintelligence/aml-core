// Project-authored local-filesystem replay regression. The historical module
// in test/fixtures is an exact copy of the code before this hardening; it is
// intentionally unsafe and must never be used for a real approval store.
import crypto from "node:crypto";
import fs from "node:fs";
import { chmod, mkdir, mkdtemp, readdir, rename, rm, symlink, unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createFileOneShotGrants as historical } from "../test/fixtures/legacy-file-one-shot-grants.mjs";
import { createFileOneShotGrants as corrected } from "../pilots/action-boundary/file-one-shot-grants.mjs";

const digest = "a".repeat(64); // Test-only proposal digest, never a real approval.
const sha256 = data => crypto.createHash("sha256").update(data).digest("hex");
const fixture = new URL("../test/fixtures/legacy-file-one-shot-grants.mjs", import.meta.url);
const fixtureBytes = fs.readFileSync(fixture);
const fixtureSha = sha256(fixtureBytes);
const fixtureBlob = crypto.createHash("sha1").update(`blob ${fixtureBytes.length}\0`).update(fixtureBytes).digest("hex");
if (fixtureSha !== "478aa241162c4c1060cf2d9684191d762a6482124d7ad21a2dfef1ca005b961c") {
  throw Error("Historical source fixture changed");
}
if (fixtureBlob !== "b5eaf1c356300c9866aea3909fa766c12e78ee11") {
  throw Error("Historical Git blob changed");
}

async function withRoot(run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "aml-grant-directory-"));
  try { return await run(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

async function attempt(run) {
  try { return { accepted: true, value: await run() }; }
  catch (error) { return { accepted: false, reason: error.message }; }
}

async function writableRoot(factory) {
  return withRoot(async directory => {
    await chmod(directory, 0o777);
    const store = factory({ directory });
    const issued = await attempt(() => store.issue(digest));
    if (!issued.accepted) return { issued: false, reason: issued.reason, accepted_claims: 0 };
    const approval = issued.value;
    const first = await store.consume({ approval, proposal_sha256: digest });
    // Simulates a different local principal replacing a child of a writable
    // parent; this harness itself does not switch operating-system users.
    await rename(path.join(directory, "claimed"), path.join(directory, "claimed.old"));
    await mkdir(path.join(directory, "claimed"), { mode: 0o700 });
    const replay = await store.consume({ approval, proposal_sha256: digest });
    return { issued: true, first_claim: first, replay_claim: replay,
      accepted_claims: Number(first) + Number(replay),
      old_marker_count: (await readdir(path.join(directory, "claimed.old"))).length,
      replacement_marker_count: (await readdir(path.join(directory, "claimed"))).length };
  });
}

async function writableClaimed(factory) {
  return withRoot(async directory => {
    const store = factory({ directory });
    const approval = await store.issue(digest);
    // The traversal path and marker directory are made accessible after
    // issuance. A real host must never make these grant paths public.
    await chmod(directory, 0o755);
    await chmod(path.join(directory, "claimed"), 0o777);
    const first = await attempt(() => store.consume({ approval, proposal_sha256: digest }));
    if (!first.accepted) return { issued: true, first_claim: false, reason: first.reason,
      accepted_claims: 0, marker_count: (await readdir(path.join(directory, "claimed"))).length };
    for (const name of await readdir(path.join(directory, "claimed"))) {
      await unlink(path.join(directory, "claimed", name));
    }
    const replay = await store.consume({ approval, proposal_sha256: digest });
    return { issued: true, first_claim: first.value, replay_claim: replay,
      accepted_claims: Number(first.value) + Number(replay),
      marker_count: (await readdir(path.join(directory, "claimed"))).length };
  });
}

async function symlinkedClaimed(factory) {
  return withRoot(async base => {
    const directory = path.join(base, "private");
    const outside = path.join(base, "outside");
    await mkdir(directory, { mode: 0o700 });
    await mkdir(outside, { mode: 0o700 });
    await symlink(outside, path.join(directory, "claimed"));
    const store = factory({ directory });
    const issued = await attempt(() => store.issue(digest));
    if (!issued.accepted) return { issued: false, reason: issued.reason, outside_marker_count: 0 };
    const claim = await store.consume({ approval: issued.value, proposal_sha256: digest });
    return { issued: true, first_claim: claim,
      outside_marker_count: (await readdir(outside)).length };
  });
}

async function privateControl(factory) {
  return withRoot(async directory => {
    const store = factory({ directory });
    const approval = await store.issue(digest);
    const first = await store.consume({ approval, proposal_sha256: digest });
    const replay = await store.consume({ approval, proposal_sha256: digest });
    return { issued: true, first_claim: first, replay_claim: replay,
      accepted_claims: Number(first) + Number(replay) };
  });
}

const scenarios = [
  { id: "writable-root", title: "Replace the claim directory", run: writableRoot,
    explanation: "A writable root lets a local actor rename the child directory containing spent markers. The old store accepts the same approval again after the replacement." },
  { id: "writable-claimed", title: "Delete a spent marker", run: writableClaimed,
    explanation: "A traversable root and writable claim directory let a local actor remove a marker. The old store accepts a second claim." },
  { id: "symlink-claimed", title: "Redirect claim storage", run: symlinkedClaimed,
    explanation: "A symlink to an outside directory was followed by the old store. The fixed store rejects it before issuing a grant." },
  { id: "private-control", title: "Private directory control", run: privateControl,
    explanation: "With private, owner-controlled directories, the first claim succeeds and a replay is rejected by both versions." }
];

const selected = [];
for (const scenario of scenarios) {
  selected.push({ id: scenario.id, title: scenario.title, explanation: scenario.explanation,
    before: await scenario.run(historical), after: await scenario.run(corrected) });
}
if (selected[0].before.accepted_claims !== 2 || selected[0].after.accepted_claims !== 0 ||
    selected[1].before.accepted_claims !== 2 || selected[1].after.accepted_claims !== 0 ||
    selected[2].before.outside_marker_count !== 1 || selected[2].after.outside_marker_count !== 0 ||
    selected[3].before.accepted_claims !== 1 || selected[3].after.accepted_claims !== 1) {
  throw Error("Historical replay or hardened fail-closed behavior changed");
}
const report = {
  protocol: "aml-grant-directory-regression/1",
  prior_source_commit: "8129044ae70534040d6e86f5e43d298841aa3cd0",
  prior_fixture_sha256: fixtureSha,
  prior_fixture_git_blob: fixtureBlob,
  scope: "Project-authored local filesystem simulation on POSIX; no second operating-system user or external tool side effect is involved.",
  selected
};
if (process.argv.includes("--check")) {
  const published = JSON.parse(fs.readFileSync(new URL("../docs/grant-directory-report.json", import.meta.url)));
  if (JSON.stringify(published) !== JSON.stringify(report)) throw Error("Grant directory report drift");
  console.log("Verified 4 historical/fixed directory scenarios; two prior replays, zero fixed replays");
} else {
  console.log(JSON.stringify(report, null, 2));
}
