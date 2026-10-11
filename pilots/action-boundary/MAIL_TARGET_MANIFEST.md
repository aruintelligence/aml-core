# Bind every recipient in a narrow mail tool

[Open the seven-case visual lab](https://aruintelligence.github.io/aml-core/mail-target-lab.html?case=hidden_bcc).

The first [target-binding example](TARGET_BINDING.md) uses a host resolver that reads `arguments.to`. That is incomplete for a mail tool that also sends to `cc` or `bcc`. An added BCC under the same approved `to` still reaches a simulated callback. This is a counterexample to that **example mapper**, not a claim that the generic wrapper promised to understand arbitrary tool schemas.

`mailTargetResource` supplies a stricter adapter for one explicit schema: `to`, `cc`, `bcc`, `subject`, and `body`. It validates each recipient field and rejects unknown arguments. It builds a canonical manifest with the three destination roles and returns `mail-targets-sha256:<digest>` as the exact policy resource. The trusted host creates that policy resource from the *intended* recipient manifest. At dispatch, `resolveMailTarget` derives a fresh resource from the proposal's frozen arguments. The existing target-bound wrapper blocks a mismatch before approval or callback.

```js
import { dispatchTargetBoundAction } from "./target-boundary.mjs";
import { mailTargetResource, resolveMailTarget } from "./mail-target-manifest.mjs";

const intended = mailTargetResource({ to: "team@example.test" });
const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: intended.resource,
    requires_approval: true }
] };

// The proposal may carry the intended resource, but the host does not trust
// that declaration to describe the tool arguments.
const result = await dispatchTargetBoundAction(proposal, {
  policy,
  resolveTarget: resolveMailTarget,
  requestApproval: hostApproval,
  consumeApproval: hostClaim,
  executeTool: async frozen => {
    // The host mail adapter must use exactly to, cc, bcc from the same frozen
    // arguments and reject any other delivery field or downstream redirect.
    const { to, cc, bcc, subject, body } = frozen.arguments;
    return hostMailer.send({ to, cc, bcc, subject, body });
  }
});
```

The manifest preserves address spelling, role, duplicates, and order. It accepts a string or array of strings for each recipient field; `to` must be nonempty, while absent `cc`/`bcc` become empty arrays. This example does not normalize addresses, validate mailbox syntax, or account for provider aliases. The full digest is a comparison key, **not** proof of permission or consent. Show the readable manifest to whoever owns the policy; a digest alone is not a useful review interface.

The mapper and real tool implementation must share the same schema. This helper does not cover attachments with external destinations, forwarding rules, aliases, redirects, contact expansion, API-specific recipient fields, or tool behavior that changes after the callback. Those need a different host mapping and policy representation. A body change with identical recipients still passes an unreviewed recipient rule, so content restrictions and authenticated approval remain separate. The report uses no live email service.

Run the evidence:

```sh
node test/action-boundary-mail-targets.test.js
node scripts/build-mail-target-report.mjs --check
```

The report compares the prior to-only example with this full-manifest adapter over seven bounded, project-authored cases. [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html) describes To, Cc, and Bcc as message destination fields; it does not define or endorse this ĀML adapter. This experiment is not external validation, a general email authorization system, or a delivery result.
