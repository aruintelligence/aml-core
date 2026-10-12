// A separate Node worker exercising the real A2UI gate with a simulated tool.
import { createA2UIFunctionGate } from "./a2ui-function-gate.mjs";
import { createLocalA2UIInvocationClaims } from "./a2ui-invocation-claims.mjs";
import { createFileA2UIInvocationClaims } from "./file-a2ui-invocation-claims.mjs";

process.on("message", async input => {
  try {
    let toolCalls = 0;
    const claims = input.mode === "file" ? createFileA2UIInvocationClaims({
      directory: input.directory, sessionFor: context => context.sessionId
    }) : createLocalA2UIInvocationClaims({ sessionFor: context => context.sessionId });
    const catalogId = "https://example.test/catalog/action.json";
    const recipient = "team@example.test";
    const gate = createA2UIFunctionGate({
      catalogId, functionName: "sendMessage", allowedCallers: "agentOnly",
      validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
        typeof args.to === "string" && typeof args.body === "string",
      tool: "send_message", effect: "send", purpose: "Simulated status update",
      resourceFor: args => args.to,
      policy: { protocol: "aml-action-policy/1", rules: [
        { tool: "send_message", effect: "send", resource: recipient, requires_approval: true }
      ] },
      requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
      claimInvocation: claims.claim,
      execute: async () => { toolCalls++; return { simulated: true }; }
    });
    const output = await gate({ version: "v1.0", callRendererFunction: {
      functionCallId: input.functionCallId,
      callFunction: { call: "sendMessage", catalogId,
        args: { to: recipient, body: input.body } }
    } }, { sessionId: input.sessionId });
    process.send({ invocation: output.invocation,
      response_code: output.response.error?.code ??
        output.response.rendererFunctionResponse?.error?.code ?? null,
      receipt_status: output.aml?.receipt?.execution_status ?? null,
      tool_calls: toolCalls }, () => process.disconnect());
  } catch (error) {
    process.send({ error: error.message }, () => process.disconnect());
  }
});
process.send({ ready: true });
