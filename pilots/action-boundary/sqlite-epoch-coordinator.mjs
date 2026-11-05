// Controlled subprocess adapter for the existing epochAnchor interface.
// Database location must be outside the authority's rollback domain. This
// same-user local fixture does not provide independent administrative control.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./sqlite-epoch-coordinator.py", import.meta.url));

export function createSqliteEpochCoordinator({ database, python = "python3" } = {}) {
  if (typeof database !== "string" || !database.startsWith("/") ||
      typeof python !== "string" || !python) throw new TypeError("trusted absolute database path required");
  function call(action, input = {}) {
    const child = spawnSync(python, [script, database], {
      input: JSON.stringify({ protocol: "aml-sqlite-epoch-test/1", action, ...input }),
      encoding: "utf8", timeout: 20_000
    });
    if (child.error || child.status !== 0) throw child.error ||
      Error(`coordinator_unavailable: ${child.status} ${child.stderr.trim()}`);
    return JSON.parse(child.stdout);
  }
  return Object.freeze({
    initialize: () => call("initialize"),
    inspect: () => call("inspect"),
    claimOnce: ({ protocol, ...input }) => call("claim", { claim_protocol: protocol, ...input }).accepted,
    advanceEpoch: ({ protocol, ...input }) => call("advance", { epoch_protocol: protocol, ...input }).accepted
  });
}
