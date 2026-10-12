# ĀML technical breakthroughs

This page publishes the project's strongest **shipped technical milestones** and the evidence that supports them.

It deliberately does **not** use “breakthrough” to mean external scientific validation, standards-body recognition, broad adoption, certification, or independent endorsement. Those are separate claims and require separate evidence.

## 1. A render decision can be made before pixels

ĀML can evaluate declared interface intent before a renderer receives the component.

Core prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

Live falsifiable proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

One-command local reproduction:

```bash
npm run proof
```

Publishable machine report:

```bash
npm run proof:report
```

## 2. Meaning and policy can remain separate from the renderer

The project ships browser bridges, a React adapter, a streaming interface firewall, deployment/shadow-mode wrappers, and a renderer-agnostic agent-UI governance adapter.

## 3. Generated-interface decisions can carry evidence

ĀML execution paths can emit deterministic receipts and hashes that can be inspected after the decision. Project-controlled reports remain project evidence until an outside party independently runs and publishes them.

## 4. Meaning can become a release-control primitive

The repository includes Meaning Fingerprints, Meaning Manifests, signed manifests, append-only Meaning Lineage, Semantic Release Proofs, release-key trust policy, threshold/quorum authorization, in-toto statement export, and GitHub attestation verification tooling.

## 5. Interface accountability can extend across systems

The runtime includes capability negotiation, policy passports, replay protection, content-addressed bundles, selective disclosure, trust delegation, transparency logs, revocation registries, causal execution graphs, and Proof-Carrying Interface™ artifacts.

## 6. Verification is designed to permit disagreement

ĀML's public verification path explicitly accepts **PASS / FAIL / MIXED** results. Internal CI, project-maintained reference runtimes, clone counts, or outreach activity are not external evidence.

## 7. The governance boundary can cross process and language boundaries

The Agent UI governance contract is exposed through JavaScript API, CLI, and HTTP, with machine-readable schemas and conformance vectors. External runtimes can hand a JSON envelope to a separate governance process without importing ĀML internals.

## 8. Governance can remain present while an interface is still being generated

The continuous governance stream evaluates incremental semantic nodes and can return ALLOW/SUPPRESS decisions before later nodes exist. The reference transport uses HTTP/NDJSON.

## 9. A live governance session can become replayable evidence

Governance-stream transcripts are SHA-256 hash chained and then deterministically replayed. Replay verification is designed to reject a stronger attack where someone falsifies an output and recomputes an otherwise valid new hash chain.

## 10. Transcript integrity, signature validity, and trust can remain separate

Replayable transcripts can be signed with Ed25519. Verification separately reports transcript validity, replay validity, signature validity, and whether the key fingerprint belongs to an explicitly supplied trust set. An embedded public key is not a trust root.

## 11. Multiple trusted keys can witness the same governed interface decision

ĀML includes a project-defined multi-party governance witness quorum. Signed, replay-valid governance transcripts can be evaluated under a threshold policy requiring enough distinct eligible signing keys to attest to the same transcript root.

Protocol:

```text
aml-governance-witness-quorum/1
```

This is a threshold-attestation primitive, not Byzantine consensus, identity proofing, a timestamp authority, independent external validation, standards-body recognition, or evidence that outside organizations currently operate witness nodes.

## 12. Cross-runtime disagreement can be localized instead of hidden

Two governance transcripts can be compared entry by entry. When executions diverge, `aml-runtime-disagreement-report/1` identifies the first observable disagreement and hashes both sides of that boundary.

The localizer does not declare the project runtime correct. Correctness still requires an external contract, conformance vector, witness policy, or adjudication rule.

## 13. Governance evidence can be selectively disclosed

A Merkle commitment can be built over transcript entry hashes and selected entries can be revealed with inclusion proofs while undisclosed message bodies remain absent.

Protocol:

```text
aml-governance-selective-disclosure/1
```

This is selective disclosure, not zero-knowledge proof. Authenticity still requires a trusted signed, witnessed, published, or otherwise authenticated commitment or transcript root.

## 14. Policy can change during generation without disappearing from history

ĀML continuous-governance sessions can make default policy changes explicit while an interface is still streaming.

A live transition enters the stream as `aml-governance-stream-policy-update/1` and is acknowledged as `aml-governance-stream-policy-applied/1`. Each accepted update advances a monotonically increasing policy epoch and records hashes of the previous policy state, new policy state, and active context.

Because transitions are part of the same transcript as interface nodes and decisions, policy mutation remains deterministically replayable. This records and applies policy changes; it does not itself authorize them.

## 15. A partial disclosure can be anchored by a signed commitment

ĀML can sign the compact commitment behind a selective governance disclosure with Ed25519. The signed material contains the source transcript root, source entry count, and Merkle root committing to every transcript entry hash.

Protocols:

```text
aml-governance-disclosure-commitment/1
aml-signed-governance-disclosure-commitment/1
```

The verifier separates signature validity, verifier-controlled key trust, revocation policy, signer scope, and whether the disclosure matches the signed commitment. A valid signature still does not establish real-world identity, independent witnessing, certification, external adoption, or official ĀRU authorization.

## 16. A live policy transition can require threshold cryptographic authority

ĀML can optionally protect live governance-policy changes with a threshold of trusted Ed25519 signatures before policy state is allowed to mutate.

The transition that gets signed is bound to the exact governance-stream transmission, expected current policy epoch, SHA-256 of the exact previous policy state, and exact requested update fields.

Protocols:

```text
aml-governance-policy-transition/1
aml-governance-policy-transition-authorization/1
```

A protected stream can specify a verifier-controlled policy containing a signature threshold, trusted key fingerprints, revoked fingerprints, required signer scope, and trusted-key requirements. Duplicate signing keys cannot satisfy a distinct-key threshold.

If authorization is missing, the eligible-signature threshold is not met, or the signed transition is bound to a different epoch, prior state, transmission, or requested change, the policy update is rejected **before state mutation**.

## 17. Root trust can delegate operational governance authority

Protected policy transitions no longer require every operational signing key to appear directly in the verifier's root trust list.

When `allow_delegated_authority` is explicitly enabled, a transition signature can carry a signed `aml-trust-delegation/2` chain. The verifier accepts that signer only when:

- the chain begins at a root key already present in the verifier-supplied trust set;
- cryptographic key continuity holds through every delegation hop;
- every hop delegates the required capability, normally `governance-policy-transition`;
- the final delegated key is exactly the key that signed the bound transition;
- no issuer, intermediate, or leaf key appears in the supplied revocation set;
- configured expiry/time checks pass;
- and the transition signature remains valid for the exact stream, policy epoch, prior-policy hash, and requested update.

Delegation is disabled by default. Directly trusted keys continue to work without a delegation chain.

Project surfaces:

- `createSignedTrustDelegation(...)`;
- `verifyDelegationChain(...)`;
- `signGovernancePolicyTransition(..., { delegation_chain })`;
- `verifyGovernancePolicyTransitionAuthorization(...)` with `allow_delegated_authority`;
- `docs/DELEGATED_GOVERNANCE_AUTHORITY.md`;
- `publications/DELEGATED_GOVERNANCE_AUTHORITY.md`.

This separates long-lived root trust from short-lived operational signing authority while keeping root selection, capability scope, revocation, time, and threshold policy under verifier control.

It does not establish legal identity, employment, organizational approval, regulatory authority, certification, independent validation, or official ĀRU authorization. Those remain separate external claims.

## 18. A host-owned approval can be claimed once before an agent tool runs

The proposed-action pilot has an optional `consumeApproval` callback. After exact digest approval and policy recheck, a host can atomically claim a short-lived grant before invoking the tool. A reused or expired grant blocks, and a policy revocation during an asynchronous claim is checked again before dispatch.

Run `node pilots/action-boundary/one-shot-grant-demo.mjs`: the first call invokes one simulated callback; a second call reusing the same grant is blocked with no additional callback. The [visual replay lab](https://aruintelligence.github.io/aml-core/action-lab.html?scenario=replay) shows the same project-authored scenario. The local store works in one Node process only; it is not a durable cross-worker replay defense, authenticated human approval, proof of delivery, or independent validation.

## 19. A local one-use grant can be claimed across two processes

`createFileOneShotGrants({ directory })` lets workers on one machine use a trusted local directory as a shared short-lived grant store. An exclusive claim marker is created before the host tool callback. In the [recorded two-process race](https://aruintelligence.github.io/aml-core/approval-race.html), one process reaches the simulated callback and the other receives `approval_reused_or_expired`. Re-run the result with `node pilots/action-boundary/file-grant-race-demo.mjs`; the test starts two actual Node child processes, not two promises in one runtime.

This is a project-authored local-filesystem prototype. It does not authenticate a person, work across machines or network filesystems, prove delivery, or protect tools that bypass the wrapper. The host must provide private storage, expiry and cleanup policy, trusted clocks, idempotency, and tool-specific authorization.

## 20. A proposed-action boundary can be implemented in two languages

The project now has separate JavaScript and dependency-free Python implementations of its published action-boundary subset. The Python adapter imports no JavaScript boundary code. Both pass the 13-case black-box challenge and produce [matching actual plans, dispatch receipts, callback counts, and frozen proposals](https://aruintelligence.github.io/aml-core/action-cross-runtime.html) for each fixture. A checked-in comparison report is regenerated and checked in CI; any divergence is visible case by case.

Reproduce with `node scripts/run-action-boundary-challenge.mjs -- python3 pilots/action-boundary/challenge-python-adapter.py` and `node scripts/build-action-cross-runtime-report.mjs --check`. The supported canonical JSON subset is deliberately narrow: safe-range integers and BMP object keys, with unsupported inputs rejected in Python. Both implementations are **project-maintained**; matching internal code paths are not outside verification, generalized interoperability, authenticated approval, or proof of a live side effect.

## 21. An uncertain tool callback can remain claimed without a blind replay

The optional, host-owned `createFileDispatchLedger({ directory })` uses an exclusive local-file claim keyed by a **host-generated operation ID** and bound to the canonical proposal digest. It claims before the tool callback. In the [six-scenario visual trace](https://aruintelligence.github.io/aml-core/dispatch-ledger.html), two actual Node processes compete for one ID and only one reaches the simulated callback; the other attempt is suppressed. Reuse with a changed payload reports a mismatch. A worker exiting after claim or a callback throwing after a possible effect leaves an `unknown` result and never automatically retries. A new operation ID can intentionally permit the same payload again.

Run `node pilots/action-boundary/file-dispatch-ledger-demo.mjs`, then check the published report with `node scripts/build-file-dispatch-report.mjs --check`. Unlike the one-use **approval grant** in milestone 19, this ID represents a host operation and must not be derived from the proposal digest or model text. The ledger stores hashes and outcome labels, not evidence of delivery. It is a project-authored local-filesystem prototype, not an external idempotency service, cross-machine transaction, durable outbox, automatic recovery, authenticated approval, or proof that an external effect happened. The host must own private storage, stable intent IDs, retention, reconciliation, and tool-specific authorization.

## 22. A counterexample can improve cross-runtime agreement

The 13 published action-boundary cases agreed, but an adversarial proposed action containing object keys `"10"` and `"2"` did not. The JavaScript reference's ordinary-object serialization emits the array-index key `"2"` first; the former Python implementation emitted lexical `"10"` first. That produced different SHA-256 proposal digests for the same action, a genuine portability defect in the project-maintained subset.

Python now follows the existing JavaScript wire order for array-index keys (canonical decimal `0` through `4294967294`) at every object depth; ordinary BMP string keys retain lexical order. The [visual counterexample lab](https://aruintelligence.github.io/aml-core/key-order-lab.html) shows exact old Python, JavaScript, and fixed Python bytes and hashes for seven named cases, including nested objects, leading zeroes, the 32-bit edge, and controls. `node scripts/build-action-key-order-report.mjs --check` runs a separate Python process on those seven plus 512 seeded adversarial proposals. The prior Python ordering diverges on 439 of **this deliberately biased corpus**; fixed Python and JavaScript agree on all 519, and the existing 13-case challenge remains green.

This is a project-authored counterexample and bounded regression, not a statistical estimate of real-world failure rates, general JSON canonicalization, external implementation, or security certification. The subset still rejects floats and non-BMP object keys in Python, and it requires Unicode-scalar string values. Existing JavaScript digest bytes are unchanged.

## 23. A writable claim directory can turn a one-use approval into two claims

The local file-grant pilot required private host storage in its documentation, but the former implementation used recursive `mkdir` without checking an existing directory's mode, owner, or symlink status. In a project-authored POSIX simulation, a writable root permitted replacement of the `claimed` directory after the first claim. The *same* grant then returned `true` a second time. A traversable root with a writable claim directory also permitted deleting the spent marker and repeating the claim. A symlinked claim directory redirected storage outside the root.

`createFileOneShotGrants` now checks that the root, `issued`, and `claimed` are owner-controlled private directories without group/other permissions or symlinks. It checks before issuing and again before consuming, and consumption does not recreate a missing claim directory. An unsafe state throws `private_grant_directory_required`; the action boundary converts a claim-store error into a blocked dispatch. A private-directory control still accepts its first claim and rejects reuse.

The [visual replay lab](https://aruintelligence.github.io/aml-core/grant-directory-lab.html?scenario=writable-root) shows four exact before/after runs. `node scripts/build-grant-directory-report.mjs --check` executes both the current module and a historical source fixture whose Git blob matches the prior main commit, then checks the published report. The simulation mutates paths within one process; it does not impersonate a second OS user or execute a real tool. Its guarantee assumes a stable trusted local path and no hostile same-user process. It is not a distributed store, filesystem race proof, human-authentication system, or security certification.

## 24. A catalog-authorized function can still face an exact action gate

A2UI v1.0 (candidate) lets an agent request a renderer function when the active catalog permits agent callers. The [bounded host-side adapter](pilots/action-boundary/a2ui-function-gate.mjs) composes that caller check with the existing ĀML proposed-action boundary. A registered, `agentOnly` function with a matching destination and digest-bound simulated approval reaches one local callback. The same function with a changed destination is blocked before dispatch. Renderer-only, unknown catalog/function, and invalid arguments stop at the catalog/schema stage. An uncertain callback stays `unknown` without a retry.

The [nine-case visual lab](https://aruintelligence.github.io/aml-core/a2ui-function-lab.html?case=changed_destination#cases) reads a report regenerated by `node scripts/build-a2ui-function-report.mjs --check` in CI. The [guide](pilots/action-boundary/A2UI_FUNCTION_GATE.md) documents the exact v1.0 envelope and host responsibilities. This is a project-authored local integration experiment, not a full A2UI renderer, official conformance, independent deployment, human authorization, or evidence that a real message was delivered. A2UI's catalog enforcement and existing framework approvals remain distinct controls.

## 25. Reusing a renderer function ID can be stopped before a second callback

The prior A2UI host-side pilot accepted the same agent-supplied `functionCallId` twice in one trusted host session and reached the simulated callback twice. That contradicts the candidate specification's unique-invocation-ID intent. A pinned copy of the prior module (Git blob `68fdbb0ac5cd7518e6c4974cae04f5417c8d3d6e`, with only its relative import adjusted) reproduces the counterexample.

The corrected bridge now requires a host-owned `claimInvocation` callback. It freezes validated arguments, atomically claims the ID in a trusted host session, and rejects reuse **before** AML approval or dispatch. A claim-store error fails closed. The [six-case visual comparison](https://aruintelligence.github.io/aml-core/a2ui-invocation-replay.html?case=sequential#cases) includes sequential and concurrent replay, a changed payload under the same ID, separate-session and new-ID controls, and a store outage. `node scripts/build-a2ui-invocation-replay-report.mjs --check` reruns historical and corrected modules and checks the report in CI.

This is a project-authored process-local simulation with no external message. The helper store cannot coordinate separate workers or survive restart; a production host needs persistent atomic claims, authenticated session identity, separate human approval, and tool-specific idempotency. An agent can supply a different ID for a new attempt, so the claim is not an exactly-once external-effect guarantee.

## 26. An outside implementer can debug one boundary case before claiming all 13

The Action Boundary Challenge now supports `--case <id>` for a focused local run and emits field-level expected/observed diagnostics alongside its existing machine failure codes. The report distinguishes `case_scope: "single"` from `case_scope: "full"`; a passing single case always has `full_challenge_passed: false`. The [visual builder loop](https://aruintelligence.github.io/aml-core/action-challenge.html?case=changed-destination#build) offers a deep link and copyable command for every published case, then a full-run command. The [adapter contract](publications/ACTION_BOUNDARY_CHALLENGE.md) shows the sibling-repository path and the evidence to share.

This improves the reproducibility path for a new implementation. It does not add an outside implementation or turn the project-authored reference run into an independent result. The browser board shows expected fixtures and never executes an adapter; a full PASS still establishes only compatibility with the 13 published cases.

## 27. The same exact destination can carry a different message

The action boundary's exact policy rule matches `tool`, `effect`, and `resource`; it does not constrain `purpose` or `arguments`. With an intentionally unreviewed send rule, a message body changed under the same recipient still matches and reaches one simulated host callback. The proposal SHA-256 digest changes, but hashing alone is not an authorization decision. This is a scope counterexample to the casual interpretation that “exact rule” implies exact message content.

An approval-required rule with a fixed host decision bound to the original proposal digest blocks the changed body before a callback. The [eight-case visual Policy X-ray](https://aruintelligence.github.io/aml-core/action-policy-scope.html?case=changed_body#cases) compares original, body, purpose, extra argument, destination, effect, tool, and key-order changes. `node scripts/build-action-policy-scope-report.mjs --check` reruns the reference dispatch path, asserts callback counts and receipts, and checks its machine report. The [guide](pilots/action-boundary/POLICY_SCOPE.md) shows the host-side integration choice.

These are project-authored local simulations, not messages, real approvals, independent verification, or a content safety guarantee. The host must map the actual destination, enforce content-specific restrictions, and decide whether a new digest deserves authorization. A future host can approve a changed proposal; the fixed digest in this experiment is only a precise stale-approval counterexample.

## 28. A declared destination can differ from the recipient a tool will use

The exact action rule compares the proposal's `tool`, `effect`, and declared `resource`. In a project-authored local counterexample, `resource` stays `team@example.test` while `arguments.to` becomes `outside@example.test`. With an intentionally unreviewed rule, the existing reference boundary allows this proposal and reaches one simulated callback carrying the outside recipient. A digest reflects the changed arguments, but the rule does not derive the destination from them.

The opt-in `dispatchTargetBoundAction` snapshots the proposal and requires a host-owned, tool-specific `resolveTarget` callback to derive the actual destination from frozen arguments. It blocks a missing, failed, or mismatched mapping before approval or dispatch, then delegates to the existing boundary for policy recheck, approval, and callback handling. The [seven-case visual lab](https://aruintelligence.github.io/aml-core/target-binding-lab.html?case=forged_recipient) compares receipts and callback counts. `node scripts/build-target-binding-report.mjs --check` regenerates its machine report, and the [guide](pilots/action-boundary/TARGET_BINDING.md) shows integration responsibilities.

The mapper must genuinely reflect every destination a real tool can use, including aliases and secondary recipients; the wrapper cannot prove that on its own. It does not authenticate approval, validate message content, cover bypassing tool paths, or prove external delivery. A changed body with an aligned target still reaches an unreviewed simulated callback. These are project-authored local cases, not independent validation or an official protocol extension.

## 29. A correct target check can still miss a second recipient

The previous target-binding wrapper required a host-owned resolver, but its first mail example returned only `arguments.to`. Add `bcc: ["outside@example.test"]` while keeping the approved `to: "team@example.test"`, and that example reports a matching target. The frozen proposal reaches one simulated callback carrying the unapproved BCC field. The generic wrapper did not claim to discover arbitrary tool destinations; this counterexample shows why mapper completeness is a necessary host responsibility.

For one narrow mail schema, `mailTargetResource` validates To, CC, and BCC, builds a canonical manifest, and uses its SHA-256 as an exact policy resource key. `resolveMailTarget` derives the same key from frozen dispatch arguments. The [seven-case visual lab](https://aruintelligence.github.io/aml-core/mail-target-lab.html?case=hidden_bcc) shows the BCC and CC additions blocked before callbacks, an explicitly authorized multi-recipient control that passes, schema failures, and a changed-body limit. `node scripts/build-mail-target-report.mjs --check` regenerates the machine report; the [guide](pilots/action-boundary/MAIL_TARGET_MANIFEST.md) explains the exact schema and downstream assumptions.

This is a project-authored local simulation, not a sent message, independent validation, or a general email security guarantee. The digest is a comparison key and does not authenticate permission. A real mail adapter must use exactly the mapped delivery fields and account for provider aliases, redirects, forwarding, or other ways to change recipients. Content and approval remain separate host decisions.

## 30. A recipient resource can be inspected with custom inputs

The [editable Recipient Workbench](https://aruintelligence.github.io/aml-core/mail-target-workbench.html?preset=hidden_bcc) takes intended and proposed mail argument JSON, validates the same narrow schema as the Node adapter, and displays both complete manifests and their exact resource keys. It previews the target comparison locally, with zero simulated callbacks for a mismatch or invalid shape. Presets show an added BCC, an intended group, changed message content, and an unknown delivery field. Custom input stays in the browser and is not placed in the URL.

The schema parser is a shared source copied byte-for-byte into `docs/` by `node scripts/build-mail-target-workbench.mjs`. The test compares its serialized bytes with the canonical JSON contract, verifies SHA-256 parity with Web Crypto across varied recipient shapes, and checks malformed inputs. The seven-case lab still runs the actual Node target-bound wrapper and receipts; the workbench is an interactive preview, not a dispatch engine. A matching destination resource neither binds the message body nor supplies authenticated consent, provider resolution, or a real send.

## 31. Carry the complete recipient check into the function tool

The generic guarded function-tool adapter takes a host `resourceFor` callback. Its documented To-only example passes only To and body to the host callback, so the mapping fits that narrow example. The [seven-case integration lab](https://aruintelligence.github.io/aml-core/mail-tool-integration.html?case=added_bcc#cases) tests a changed callback that also accepts CC/BCC while its mapping remains To-only. An unapproved BCC then reaches one simulated callback.

The new `createMailGuardedToolExecute` snapshots the proposed mail arguments, validates the five supported fields, derives a complete To/CC/BCC resource, and rechecks that resource from the frozen proposal before dispatch. Under an exact intended-recipient rule, the added BCC lacks a rule and reaches zero callbacks. Controls cover an intended group, unknown field, changed content, and stale approval digest. The [machine report](docs/mail-tool-report.json) is regenerated by `node scripts/build-mail-tool-report.mjs --check`; the [host guide](pilots/action-boundary/MAIL_GUARDED_TOOL.md) shows a function-tool execute callback.

This is a host-side, project-authored Node example. It does not intercept all agent tools, resolve provider aliases or forwarding, authenticate approval, constrain message content, or prove delivery. The SDK's native approval flow remains separate.

## 32. Check the request constructed for the provider

The complete-recipient function-tool wrapper checks its input, but a host callback can build a different request after that check. In a local counterexample, the tool input names only `team@example.test`; host routing adds `outside@example.test` as BCC inside the provider callback. The prior adapter correctly approved its input under the declared rule, then one simulated provider callback received the expanded request. This is a host integration gap, not a failure of its stated input schema.

The opt-in `createPreparedMailToolExecute` snapshots and validates the tool input, calls a host-owned `prepare` step once, then snapshots and validates the complete five-field provider request **before** invoking the existing recipient policy and optional digest-bound approval. Its sender receives only the checked prepared request and frozen proposal. Under the same rule, the BCC addition reaches zero provider callbacks; an explicitly intended expanded group passes. A fixed simulated approval for original content also blocks a changed prepared body. [Eight executable cases](https://aruintelligence.github.io/aml-core/prepared-mail-lab.html?case=route_bcc#cases) expose the input, transformed request, plans, receipts, and callbacks. `node scripts/build-prepared-mail-report.mjs --check` regenerates the [machine report](docs/prepared-mail-report.json); the [guide](pilots/action-boundary/PREPARED_MAIL_TOOL.md) gives the host contract.

These are project-authored in-memory callbacks, not messages or independent validation. A sender can ignore the checked request, and a provider can expand aliases, lists, forwarding, or other delivery routes. The host owns policy, authenticated approval, real provider integration, and reconciliation of uncertain outcomes.

## 33. Make an outside challenge run visibly inspectable

The thirteen-case Action Boundary Challenge already accepted an external process and emitted machine JSON, but its public board displayed only project-authored **expected** fixtures. A developer's actual observed results were difficult to inspect and share without building a separate viewer. The runner now accepts `--html-out <new-file.html>` and emits a standalone offline visual report in addition to its unchanged JSON stdout and exit status. It displays PASS, FAIL, or MIXED, full versus focused scope, case-level failure codes and expected/observed field diagnostics, and the exact manifest/vector hashes. An existing output file is not silently overwritten.

The [published visual example](https://aruintelligence.github.io/aml-core/action-challenge-run.html) is regenerated from the project reference self-test by `node scripts/build-action-challenge-visual-example.mjs --check` in CI and plainly labels itself as such. An outside implementation can generate its **own** report with `node scripts/run-action-boundary-challenge.mjs --html-out ./my-run.html -- ../my-adapter/adapter`. The [contract](publications/ACTION_BOUNDARY_CHALLENGE.md) explains the workflow. Tests cover full and focused runs, failure diagnostics, no-overwrite behavior, and hostile adapter text escaping. The generated HTML has no external scripts or data fetches.

This is a lower-friction evidence surface, not a new independent result. The report is not signed, an HTML file can be edited, and provenance still requires review of the outside code, run environment, and published JSON. The project's own 13/13 result remains E1/E2 evidence, not E3 adoption.

## The frontier

The next technical frontiers are:

1. independent reproduction of the growing governance contract stack;
2. external adapters for distinct generative-UI protocols;
3. a genuinely independently maintained runtime implementing the public contracts;
4. transmission-, environment-, epoch-, and time-bounded delegation constraints beyond capability-only delegation;
5. multi-party witness quorums over selective-disclosure commitments;
6. stronger privacy proofs, including research toward zero-knowledge statements about governed decisions without revealing message bodies;
7. machine-readable adjudication policies for cross-runtime disagreement;
8. bounded real-application pilots comparing shadow and enforce modes;
9. adversarial testing for false ALLOW decisions, unauthorized policy transitions, replay across epochs, revoked-key reuse, delegation-chain substitution, privilege expansion, threshold bypass, transcript substitution, disclosure substitution, and cross-runtime divergence.

The goal is not to make ĀML impossible to criticize. The goal is to make its claims increasingly precise, executable, portable, privacy-aware, and falsifiable.
