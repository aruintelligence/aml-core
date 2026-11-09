// Release-blocker regression: js/file-system-race at
// pilots/action-boundary/file-one-shot-grants.mjs (path checked, then used).
// Threat model: the attacker cannot write inside the 0700 store, but can
// rename entries in an ancestor directory that is writable by others. The
// same uid stands in for that principal here; the swap is driven at the
// exact window by a synchronous hook. Synthetic digests only.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { syncBuiltinESMExports } from "node:module";
import { createFileOneShotGrants } from "../pilots/action-boundary/file-one-shot-grants.mjs";

const DIGEST = "c".repeat(64);

function temporary() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "aml-grant-ancestor-"));
}

async function reviveExpiredGrant(parentMode) {
  const root = temporary();
  try {
    const parent = path.join(root, "shared");
    fs.mkdirSync(parent, { mode: 0o700 });
    const store = path.join(parent, "store");
    let clock = 1_000_000;
    const grants = createFileOneShotGrants({ directory: store, now: () => clock });
    const approval = await grants.issue(DIGEST, { ttlMs: 1000 });
    fs.chmodSync(parent, parentMode); // ancestor becomes writable by others
    clock += 60_000; // the grant has expired
    // Attacker-prepared decoy store with a forged far-future record.
    const decoy = path.join(parent, "decoy");
    for (const dir of [decoy, path.join(decoy, "issued"), path.join(decoy, "claimed")]) fs.mkdirSync(dir, { mode: 0o700 });
    fs.writeFileSync(path.join(decoy, "store-state.json"), '{"protocol":"aml-file-one-shot-store/2"}\n', { mode: 0o600 });
    const record = `${approval.approval_id}.json`;
    fs.writeFileSync(path.join(decoy, "issued", record), JSON.stringify({ approval_id: approval.approval_id,
      proposal_sha256: DIGEST, expires_at_ms: Number.MAX_SAFE_INTEGER - 1 }), { mode: 0o600 });
    const real = path.join(parent, "store.real");
    const swapIn = () => { fs.renameSync(store, real); fs.renameSync(decoy, store); };
    const swapOut = () => { fs.renameSync(store, decoy); fs.renameSync(real, store); };
    const target = path.join(store, "issued", record);
    const originals = { readFile: fsp.readFile, openSync: fs.openSync };
    let swaps = 0;
    fsp.readFile = async function (file, ...rest) {
      if (String(file) !== target) return originals.readFile.call(this, file, ...rest);
      swapIn(); swaps += 1;
      try { return await originals.readFile.call(this, file, ...rest); } finally { swapOut(); }
    };
    fs.openSync = function (file, ...rest) {
      if (String(file) !== target) return originals.openSync.call(this, file, ...rest);
      swapIn(); swaps += 1;
      try { return originals.openSync.call(this, file, ...rest); } finally { swapOut(); }
    };
    syncBuiltinESMExports();
    let outcome;
    try { outcome = await grants.consume({ approval, proposal_sha256: DIGEST }); }
    catch (error) { outcome = error.message; }
    finally { Object.assign(fsp, { readFile: originals.readFile }); fs.openSync = originals.openSync; syncBuiltinESMExports(); }
    fs.chmodSync(parent, 0o700);
    return { outcome, swaps };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test("an ancestor writable by others cannot be used to revive an expired grant", async () => {
  for (const mode of [0o777, 0o770, 0o757, 0o722]) {
    const { outcome, swaps } = await reviveExpiredGrant(mode);
    assert.equal(outcome, "trusted_grant_directory_ancestors_required", mode.toString(8));
    assert.equal(swaps, 0, "the store is refused before any record is read");
  }
});

test("sticky shared ancestors and private ancestors stay usable; expiry still holds", async () => {
  const root = temporary();
  try {
    let clock = 5_000;
    for (const mode of [0o700, 0o755, 0o1777]) {
      const parent = path.join(root, `p${mode.toString(8)}`);
      fs.mkdirSync(parent, { mode: 0o700 });
      fs.chmodSync(parent, mode);
      const grants = createFileOneShotGrants({ directory: path.join(parent, "store"), now: () => clock });
      const approval = await grants.issue(DIGEST, { ttlMs: 1000 });
      assert.equal(await grants.consume({ approval, proposal_sha256: DIGEST }), true, mode.toString(8));
      assert.equal(await grants.consume({ approval, proposal_sha256: DIGEST }), false);
      const late = await grants.issue(DIGEST, { ttlMs: 1000 });
      clock += 5_000;
      assert.equal(await grants.consume({ approval: late, proposal_sha256: DIGEST }), false, "expired");
      fs.chmodSync(parent, 0o700);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("a symlinked issued record is refused instead of followed", async () => {
  const root = temporary();
  try {
    const store = path.join(root, "store");
    const grants = createFileOneShotGrants({ directory: store, now: () => 10 });
    const approval = await grants.issue(DIGEST, { ttlMs: 1000 });
    const record = path.join(store, "issued", `${approval.approval_id}.json`);
    const forged = path.join(root, "forged.json");
    fs.writeFileSync(forged, JSON.stringify({ approval_id: approval.approval_id, proposal_sha256: DIGEST,
      expires_at_ms: Number.MAX_SAFE_INTEGER - 1 }), { mode: 0o600 });
    fs.rmSync(record);
    fs.symlinkSync(forged, record);
    await assert.rejects(() => grants.consume({ approval, proposal_sha256: DIGEST }));
    assert.equal(fs.existsSync(path.join(store, "claimed", `${approval.approval_id}.claim`)), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("a record with a non-private mode is refused", async () => {
  const root = temporary();
  try {
    const store = path.join(root, "store");
    const grants = createFileOneShotGrants({ directory: store, now: () => 10 });
    const approval = await grants.issue(DIGEST, { ttlMs: 1000 });
    fs.chmodSync(path.join(store, "issued", `${approval.approval_id}.json`), 0o644);
    await assert.rejects(() => grants.consume({ approval, proposal_sha256: DIGEST }), /regular_file_integrity_required/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
