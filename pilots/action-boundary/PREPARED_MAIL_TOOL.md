# Check the prepared mail request before dispatch

[Inspect eight executed cases](https://aruintelligence.github.io/aml-core/prepared-mail-lab.html?case=route_bcc#cases) · [Read the machine report](../../docs/prepared-mail-report.json)

The complete-recipient mail adapter checks the arguments it receives. A host may then build a different provider request inside its `execute` callback, for example by adding a BCC from a routing configuration. The earlier check does not cover that post-check transformation. The local counterexample passes `{ to: "team@example.test" }` into the checked callback, then submits a constructed request with `bcc: ["outside@example.test"]` to an in-memory provider callback. One callback is recorded.

`createPreparedMailToolExecute` moves the host's `prepare` step before the existing complete-recipient boundary. It snapshots and validates the tool input, calls the host's preparation function once, snapshots and validates its five-field result, then checks the complete To/CC/BCC manifest against host policy. Any required approval sees the **prepared** proposal and digest, including the prepared subject and body. Only a frozen copy of those prepared fields reaches `execute`. Under the same intended rule, the added BCC is blocked and the provider callback count becomes zero.

```js
import { createPreparedMailToolExecute } from "./prepared-mail-tool.mjs";
import { mailTargetResource } from "./mail-target-manifest.mjs";

const intended = mailTargetResource({ to: "team@example.test" });
const policy = { protocol: "aml-action-policy/1", rules: [{
  tool: "send_message", effect: "send", resource: intended.resource,
  requires_approval: true
}] };

const execute = createPreparedMailToolExecute({
  purpose: "Send release", policy,
  prepare: async (toolArgs, context) => {
    // Host-owned routing, aliases, and request construction happen here.
    return hostBuildProviderRequest(toolArgs, context);
  },
  requestApproval: hostAuthenticatedApproval,
  consumeApproval: hostAtomicOneUseClaim,
  execute: async preparedRequest => hostMailer.send(preparedRequest)
});
```

The host's prepared request must contain only `to`, `cc`, `bcc`, `subject`, and `body`. A missing or malformed recipient, unsupported field, preparation error, or invalid tool input fails before the provider callback. The original `context` is available to `prepare` and approval callbacks, but is deliberately not passed to the sender. The sender receives `(preparedRequest, frozenProposal)` and must submit only the prepared fields. The proposal digest binds the prepared body for approval; an unreviewed recipient rule alone does not constrain content.

The host must construct policy from trusted intent. If host routing intentionally adds a recipient, authorize the **prepared** complete recipient manifest. A matching rule is permission only according to that host's policy; `requestApproval` must authenticate a person if approval is required, and `consumeApproval` must enforce any one-use claim. The code cannot prove the sender obeys its parameter, or that a provider does not expand lists, aliases, forwarding rules, redirects, or other delivery routes. It does not guarantee content safety, acceptance, or delivery. A thrown sender yields an `unknown` receipt and is not retried automatically.

Run the project-authored experiment:

```sh
node test/action-boundary-prepared-mail.test.js
node scripts/build-prepared-mail-report.mjs --check
```

The eight-case visual page reads that checked-in report. Both provider callbacks append only to memory. Its fixed digest is a simulated approval comparison, never evidence of human consent. This is a host-side opt-in adapter, not a provider integration or independent security validation.

For a separate opt-in path that also checks a file-backed issuer revocation epoch before provider callback invocation, see [revocable prepared mail](REVOCABLE_PREPARED_MAIL.md). The host still owns authenticated approval and the actual sender.
