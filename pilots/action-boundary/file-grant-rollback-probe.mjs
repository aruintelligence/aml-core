#!/usr/bin/env node
// Controlled negative fixture: a complete pre-claim snapshot defeats a local
// one-use store. Never use this as an execution authorization mechanism.
import assert from "node:assert/strict";
import { cp, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createFileOneShotGrants } from "./file-one-shot-grants.mjs";

export async function probeCompleteStoreRollback() {
  const root = await mkdtemp(path.join(os.tmpdir(), "aml-complete-rollback-"));
  const directory = path.join(root, "grants");
  const snapshot = path.join(root, "preclaim-snapshot");
  const proposal_sha256 = "a".repeat(64);
  try {
    const first = createFileOneShotGrants({ directory });
    const approval = await first.issue(proposal_sha256);
    await cp(directory, snapshot, { recursive: true });
    const original_claim = await first.consume({ approval, proposal_sha256 });
    const ordinary_replay = await createFileOneShotGrants({ directory })
      .consume({ approval, proposal_sha256 });
    await rm(directory, { recursive: true });
    await cp(snapshot, directory, { recursive: true });
    const after_rollback = await createFileOneShotGrants({ directory })
      .consume({ approval, proposal_sha256 });
    assert.equal(original_claim, true);
    assert.equal(ordinary_replay, false);
    return { protocol: "aml-complete-store-rollback-probe/1", original_claim,
      ordinary_replay, after_rollback, external_anchor_present: false,
      external_effects_attempted: 0 };
  } finally { await rm(root, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await probeCompleteStoreRollback()));
}
