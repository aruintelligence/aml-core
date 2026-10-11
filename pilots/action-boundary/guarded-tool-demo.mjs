#!/usr/bin/env node
// No network call or message is sent. The host callback only records a fixture.
import { createGuardedToolExecute } from "./guarded-tool.mjs";

const policy = {
  protocol: "aml-action-policy/1",
  rules: [{ tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }]
};
const tool = createGuardedToolExecute({
  tool: "send_message", effect: "send", purpose: "Send a status update",
  resourceFor: args => args.to, policy,
  // This is a simulated host approval for demonstration, not human consent.
  requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
  execute: async args => ({ simulated: true, would_send_to: args.to })
});

console.log(JSON.stringify({
  authorized_fixture: await tool({ to: "team@example.test", body: "Build passed." }),
  changed_destination: await tool({ to: "other@example.test", body: "Build passed." })
}, null, 2));
