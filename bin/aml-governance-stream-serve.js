#!/usr/bin/env node

import { createGovernanceStreamGateway } from "../server/governanceStreamGateway.js";

const port = Number(process.env.AML_GOVERNANCE_STREAM_PORT || process.argv[2] || 8791);
const host = process.env.AML_GOVERNANCE_STREAM_HOST || "127.0.0.1";

if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  console.error("Invalid AML_GOVERNANCE_STREAM_PORT / port argument.");
  process.exit(1);
}

const server = createGovernanceStreamGateway();
server.listen(port, host, () => {
  console.log(`ĀML governance stream gateway listening on http://${host}:${port}`);
  console.log("POST /v1/governance/stream (application/x-ndjson)");
});
