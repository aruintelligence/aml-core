// Host-side adapter: construct the narrow provider request before policy and
// approval. The host still owns the preparation, policy, approval, and sender.
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { createMailGuardedToolExecute } from "./mail-guarded-tool.mjs";
import { mailTargetResource } from "./mail-target-manifest.mjs";

export function createPreparedMailToolExecute({ prepare, execute, ...options } = {}) {
  if (typeof prepare !== "function" || typeof execute !== "function") {
    throw new TypeError("Host prepare and execute callbacks are required");
  }
  // Do not pass the original tool arguments or mutable context to the sender.
  // The sender must submit precisely this prepared request to its provider.
  const guarded = createMailGuardedToolExecute({ ...options,
    execute: (prepared, _context, frozenProposal) => execute(prepared, frozenProposal) });

  return async function preparedMailExecute(args, context) {
    const source = JSON.parse(canonicalJSONStringify(args));
    mailTargetResource(source); // Fail before host preparation on unsupported tool input.
    const proposedRequest = await prepare(structuredClone(source), context);
    const prepared = JSON.parse(canonicalJSONStringify(proposedRequest));
    mailTargetResource(prepared); // No unknown delivery field may reach the sender.
    return guarded(prepared, context);
  };
}
