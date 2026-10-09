#!/usr/bin/env node

import { createAgentUiGateway } from "../server/agentUiGateway.js";

const port = Number(process.env.AML_AGENT_UI_PORT || process.argv[2] || 8790);
const host = process.env.AML_AGENT_UI_HOST || "127.0.0.1";
const defaultProfile = process.env.AML_PROFILE || "calm_default";
const defaultMode = process.env.AML_MODE || "enforce";
const defaultFailureMode = process.env.AML_FAILURE_MODE || "closed";
const apiToken = process.env.AML_API_TOKEN;
const lockedPolicy = process.env.AML_LOCKED_POLICY === "1";

if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  console.error("Invalid AML_AGENT_UI_PORT / port argument.");
  process.exit(1);
}

const server = createAgentUiGateway({
  default_profile: defaultProfile,
  default_mode: defaultMode,
  default_failure_mode: defaultFailureMode,
  ...(apiToken !== undefined ? { request_auth: { bearer_token: apiToken } } : {}),
  ...(lockedPolicy ? { locked_policy: { profile: defaultProfile } } : {})
});

server.listen(port, host, () => {
  console.log(`ĀML Agent UI gateway listening on http://${host}:${port}`);
  console.log("POST /v1/agent-ui/evaluate");
  console.log(`POST authentication: ${apiToken !== undefined ? "enabled" : "disabled"}`);
  console.log(`Deployment policy: ${lockedPolicy ? "server-owned enforce/closed" : "request-selectable"}`);
});
