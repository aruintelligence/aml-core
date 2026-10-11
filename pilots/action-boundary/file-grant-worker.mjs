// A separate process in the reproducible race demo. No external tool runs.
import { dispatchAction } from "./boundary.mjs";
import { createFileOneShotGrants } from "./file-one-shot-grants.mjs";

process.send?.({ ready: true });
process.on("message", async ({ directory, proposal, policy, grant }) => {
  try {
    const store = createFileOneShotGrants({ directory });
    let tool_calls = 0;
    const result = await dispatchAction(proposal, {
      policy,
      requestApproval: async () => grant,
      consumeApproval: store.consume,
      executeTool: async () => { tool_calls++; return { simulated: true }; }
    });
    process.send?.({ receipt: result.receipt, tool_calls }, () => process.exit(0));
  } catch (error) {
    process.send?.({ error: error.message }, () => process.exit(1));
  }
});
