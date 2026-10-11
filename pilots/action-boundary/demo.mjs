import { PROTOCOL, planAction, dispatchAction } from "./boundary.mjs";

const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }
] };
const proposal = { protocol: PROTOCOL, tool: "send_message", effect: "send",
  resource: "team@example.test", purpose: "Send a status update",
  arguments: { subject: "Update", body: "The build passed." } };

// Illustrative host callbacks. No message leaves this process.
const requestApproval = async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 });
const executeTool = async frozen => ({ simulated: true, destination: frozen.resource });

console.log(JSON.stringify({ proposal: planAction(proposal, policy),
  approved: await dispatchAction(proposal, { policy, requestApproval, executeTool }),
  changed_destination: await dispatchAction({ ...proposal, resource: "other@example.test" },
    { policy, requestApproval, executeTool }) }, null, 2));
