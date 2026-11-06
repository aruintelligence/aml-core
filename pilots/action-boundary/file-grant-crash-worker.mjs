// Test-only child process: exit abnormally after a durable local claim and
// before any tool callback. This is not a power-loss or provider test.
import { createFileOneShotGrants } from "./file-one-shot-grants.mjs";

const [directory, serializedGrant, digest] = process.argv.slice(2);
const store = createFileOneShotGrants({ directory });
if (!await store.consume({ approval: JSON.parse(serializedGrant), proposal_sha256: digest })) {
  process.exit(1);
}
process.exit(86);
