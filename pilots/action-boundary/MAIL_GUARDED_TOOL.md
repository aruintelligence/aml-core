# Put the full recipient manifest inside a function-tool boundary

[Run the seven-case visual comparison](https://aruintelligence.github.io/aml-core/mail-tool-integration.html?case=added_bcc#cases) · [Edit a custom recipient proposal](https://aruintelligence.github.io/aml-core/mail-target-workbench.html?preset=hidden_bcc)

The generic `createGuardedToolExecute` accepts a host-owned `resourceFor` callback. The To-only quickstart maps `args.to` and passes only To and body to its example callback. That mapping is adequate for that example callback. If a host extends the mail callback to use CC or BCC but leaves the mapping on To, an added recipient can reach it under an exact unreviewed To rule. The executable report reproduces that bounded case with an in-memory callback.

`createMailGuardedToolExecute` is an opt-in adapter for one narrow schema: `to`, `cc`, `bcc`, `subject`, and `body`. It snapshots the arguments, rejects unknown fields and malformed recipient values, derives the complete `mail-targets-sha256:` resource, plans against host policy, and invokes `dispatchTargetBoundAction` with `resolveMailTarget` to check the frozen arguments again before the callback. It returns `{ protocol, plan, receipt, result? }`. Invalid input throws before planning or execution; the host should handle that error as a denied tool call.

```js
import { createMailGuardedToolExecute } from "./mail-guarded-tool.mjs";
import { mailTargetResource } from "./mail-target-manifest.mjs";

const intended = mailTargetResource({ to: "team@example.test" });
const policy = { protocol: "aml-action-policy/1", rules: [{
  tool: "send_message", effect: "send", resource: intended.resource,
  requires_approval: true
}] };

const execute = createMailGuardedToolExecute({
  purpose: "Send a team update", policy,
  requestApproval: hostAuthenticatedApproval,
  consumeApproval: hostAtomicOneUseClaim,
  execute: async (frozenArgs, context) => {
    const { to, cc, bcc, subject, body } = frozenArgs;
    // This host callback must use exactly these destinations.
    return hostMailer.send({ to, cc, bcc, subject, body }, context);
  }
});

// Supply execute to your host's local function-tool definition.
```

The host must create the intended policy from trusted data. If the host intends a group, build the rule from the complete group manifest. The `requestApproval` callback must authenticate a person and return an approval for the exact frozen proposal digest; `consumeApproval` must atomically claim a one-use grant when required. An unreviewed rule is used only for the local counterexample. This adapter does not turn a digest into consent.

The real mail provider must use exactly the mapped fields. Provider aliases, list expansion, forwarding rules, redirects, hidden delivery fields, and downstream rewriting are outside this adapter. Different tool schemas need their own resolver. A changed body with the same recipients remains inside the recipient rule, so message-content constraints need separate policy or authenticated review. A returned callback does not prove external delivery.

The [OpenAI Agents SDK function-tool API](https://openai.github.io/openai-agents-js/guides/tools/) can accept a host execute callback. Its [native human-in-the-loop approval flow](https://openai.github.io/openai-agents-js/guides/human-in-the-loop/) is a separate mechanism; this project does not claim to intercept hosted tools, MCP calls, handoffs, or all SDK execution paths. Do not substitute a simulated approval for a real one.

Reproduce the project-authored evidence:

```sh
node test/action-boundary-mail-guarded-tool.test.js
node scripts/build-mail-tool-report.mjs --check
```

The visual page reads the checked-in report. Neither test sends a message, authenticates an approver, or constitutes independent validation.
