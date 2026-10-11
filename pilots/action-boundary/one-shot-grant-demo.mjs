#!/usr/bin/env node
// A local fixture: the callback records a count; no message is sent.
import { planAction } from "./boundary.mjs";
import { createGuardedToolExecute } from "./guarded-tool.mjs";
import { createLocalOneShotGrants } from "./one-shot-grants.mjs";

const args = { to: "team@example.test", body: "Build passed." };
const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: args.to, requires_approval: true }
] };
const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
  resource: args.to, purpose: "Send a status update", arguments: args };
const store = createLocalOneShotGrants();
// A real host must authenticate the approver before calling issue(). This
// fixture deliberately creates a grant without a human, solely for replay.
const grant = store.issue(planAction(proposal, policy).proposal_sha256);
let toolCallbacks = 0;
const guarded = createGuardedToolExecute({ tool: proposal.tool, effect: proposal.effect,
  purpose: proposal.purpose, resourceFor: input => input.to, policy,
  requestApproval: async () => grant, consumeApproval: store.consume,
  execute: async () => { toolCallbacks++; return { simulated: true }; } });

const first = await guarded(args);
const replay = await guarded(args);
console.log(JSON.stringify({ first: first.receipt, replay: replay.receipt,
  tool_callbacks: toolCallbacks, limits: "Process-local fixture; no message or human approval." }, null, 2));
