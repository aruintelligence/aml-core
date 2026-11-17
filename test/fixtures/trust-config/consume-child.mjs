// Child process for durable single-use tests. Inert unless AML_TC_CHILD is set
// (node --test also loads every file under test/).
import fs from "node:fs";
import { authorizeCapabilityToken } from "../../../runtime/capabilityToken.js";
import { openDurableConsumptionStore } from "../../../runtime/consumptionStore.js";

if (process.env.AML_TC_CHILD === "1") {
  const job = JSON.parse(fs.readFileSync(process.env.AML_TC_JOB, "utf8"));
  const store = job.storeDir ? openDurableConsumptionStore(job.storeDir) : null;
  if (job.startAt) while (Date.now() < job.startAt) { /* align concurrent starts */ }
  const decision = authorizeCapabilityToken(job.token, { ...job.expect, consumptionStore: store,
    consumptionGuard: store ? null : { type: "aml-capability-consumption/1", consumed: {} } });
  if (decision.authorized === true) {
    if (job.actionLog) {
      // The protected action runs only after the durable consume returned.
      if (job.hangBeforeAction) { process.stdout.write("CONSUMED\n"); setInterval(() => {}, 1000); }
      else fs.appendFileSync(job.actionLog, `${job.token.nonce}\n`);
    }
  }
  if (!job.hangBeforeAction || decision.authorized !== true) {
    process.stdout.write(`${JSON.stringify({ authorized: decision.authorized, reasons: decision.reasons, replay_protection: decision.replay_protection })}\n`);
  }
}
