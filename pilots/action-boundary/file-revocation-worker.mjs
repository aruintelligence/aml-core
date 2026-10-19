import fs from "node:fs";
import path from "node:path";
import { createFileRevocationHandoff } from "./file-revocation-handoff.mjs";
import { createTestingClaimOnce } from "./testing-claim-anchor.mjs";
import { createTestingEpochAnchor } from "./testing-epoch-anchor.mjs";

const [directory, grant_id, mode = "normal", anchorDirectory] = process.argv.slice(2);
const input = {
  tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a", audience: "mail-service",
  tool: "send_mail", policy: { allowed: ["send_mail"], revision: 1 },
  preparedRequest: { to: ["team@example.test"], bcc: [], subject: "Update", body: "Approved" }
};
const host = createFileRevocationHandoff({ directory,
  ...(mode === "anchored" ? { claimOnce: createTestingClaimOnce(anchorDirectory) } : {}),
  ...(mode === "epoch-anchored" ? { epochAnchor: createTestingEpochAnchor(anchorDirectory) } : {}) });
if (mode === "revoke") {
  console.log(JSON.stringify(host.revokeIssuer({ tenant: input.tenant, issuer: input.issuer })));
  process.exit(0);
}
const result = await host.dispatch({ ...input, grant_id, execute: () => {
  if (mode === "crash") process.exit(48); // Claim and lock already exist.
  fs.appendFileSync(path.join(directory, "effects.log"), "callback\n");
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  return { simulated: true };
} });
console.log(JSON.stringify(result));
