#!/usr/bin/env node

import { createAmlHttpServer } from "../server/httpServer.js";

const port = Number(process.env.AML_PORT || process.argv[2] || 8787);
const host = process.env.AML_HOST || "127.0.0.1";
const defaultProfile = process.env.AML_DEFAULT_PROFILE || "human_first";
const allowedOrigin = process.env.AML_ALLOWED_ORIGIN || null;

if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  console.error("Invalid AML_PORT / port argument.");
  process.exit(1);
}

const server = createAmlHttpServer({
  default_profile: defaultProfile,
  allowed_origin: allowedOrigin
});

server.listen(port, host, () => {
  console.log(`ĀML HTTP service listening on http://${host}:${port}`);
  console.log(`Default profile: ${defaultProfile}`);
  console.log("Endpoints: GET /health, GET /v1/capabilities, POST /v1/evaluate, POST /v1/verify-receipt, POST /v1/verify-witness-bundle, POST /v1/verify-brand-authorization");
});
