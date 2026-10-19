// Test-only child process for a separately stored authority checkpoint.
import fs from "node:fs";
import path from "node:path";
import { createFileAuthorityAnchor, createFileRevocationHandoff } from
  "./file-revocation-handoff.mjs";

const [directory, anchorDirectory, grant_id] = process.argv.slice(2);
const input = { tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a",
  audience: "mail-service", tool: "send_message", policy: { revision: 1 },
  preparedRequest: { to: "team@example.test", body: "Approved" } };
try {
  const anchor = createFileAuthorityAnchor({ directory: anchorDirectory });
  const host = createFileRevocationHandoff({ directory, anchor });
  const result = await host.dispatch({ ...input, grant_id, execute: () => {
    fs.appendFileSync(path.join(anchorDirectory, "effects.log"), "callback\n");
    return true;
  } });
  process.stdout.write(JSON.stringify(result) + "\n");
} catch (error) {
  process.stdout.write(JSON.stringify({ status: "blocked", reason: error.message,
    dispatch_count: 0 }) + "\n");
}
