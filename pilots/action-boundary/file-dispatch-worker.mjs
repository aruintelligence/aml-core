#!/usr/bin/env node
// Child process for the project-authored local dispatch race/crash rehearsal.
import fs from "node:fs";
import { createFileDispatchLedger } from "./file-dispatch-ledger.mjs";

const [directory, events, operationId, proposalJSON, mode = "race"] = process.argv.slice(2);
const proposal = JSON.parse(proposalJSON);
const ledger = createFileDispatchLedger({ directory });

if (mode === "claim-exit") {
  const claim = ledger.claim({ operationId, proposal });
  if (claim.status !== "claimed") process.exit(2);
  // Simulate process loss after the durable claim and before any callback.
  process.exit(83);
}

process.send?.({ ready: true });
process.on("message", async message => {
  if (message !== "go") return;
  try {
    const result = await ledger.run({ operationId, proposal, executeTool: async frozen => {
      fs.appendFileSync(events, JSON.stringify({ operationId, proposal: frozen }) + "\n");
      await new Promise(resolve => setTimeout(resolve, 80));
      return { simulated: true };
    } });
    process.send?.({ status: result.status }, () => process.exit(0));
  } catch (error) {
    process.send?.({ error: error.message }, () => process.exit(2));
  }
});
