# PR469 Mission 1 — bounded security and authorization-path coverage

**Prepublication author snapshot; actual independent review and cloud results must be recorded separately.**
No merge or deployment. This is conventional security/CI work, not a new protocol,
patent novelty assertion, production audit or universal non-bypass proof.

## Scope and interpretation

Baseline is published pilot commit `1cb58a207fd3e8bc90479e089840fe3c7d474d37` on
`operation-aml/action-contract-pilot-003`, targeting experimental development.
The primary inventory covers every static production call to shared
`consume` / `consume_in_transaction`, their verification/state helpers, fixed
provider CLI, URI helper, and the related gate/status/witness/coordinator routes.
Host-side gates and broader release/brand/governance authorization are separate
families, not implicitly made secure by this provider pilot.

“Both outcomes” below means named positive/rejection or preserved-limit cases,
not numerical/exhaustive branch coverage. Compound predicates have systematic
negative vectors, not every cross-product. No branch-coverage package is required
or installed; no 100% line/branch claim is made. Subprocess faults, operating-system
behavior, schemas/triggers, imported plugins and malicious-host schedules cannot
be exhausted by this bounded inventory. Missing evidence remains visible.

## Primary paths: code, trust boundary and branch-outcome tests

New `A01`–`A27` names refer to numbered methods in
[the authorization-path suite](../../test/fixtures/action-boundary-authorization-paths.py).
`P` refers to [native pilot tests](../../test/action-boundary-atomic-authorized-execution.test.js);
`R` to [18 integrated review-derived cases](../../test/fixtures/action-contract-pilot-003-review.py).
The [Node wrapper](../../test/action-boundary-authorization-paths.test.js) makes A
part of targeted CI and default Node discovery; skipped unittest output rejects.

| Entry / decision branch | Trusted owner / untrusted input | Positive and negative / limit coverage |
| --- | --- | --- |
| `authorized_execution.initialize`: epoch type/range; new/configured/conflicting store; transaction cleanup | Operator owns path, initial pin, epoch and schema; no agent initialization | A05 invalid epoch creates no DB; A06 cannot reset advanced epoch; P initialization continuity/replacement-key rejection; R cold eight-process initialization. Cold multi-step schema initialization is not atomic. |
| `_verify_authorization_binding`: exact fields/version/types/ASCII/digest/request shape and binding | Issuer signs exact bytes; statement/request untrusted | A01 systematically signed invalid metadata and schemas plus valid recovery; P changed body/op/destination/effect, duplicate keys/nonfinite input; legacy signed-route tests retain compatibility. |
| `_verify_signature`: base64 errors, length, real signature, key snapshot, backend failure | Operator key path; untrusted signature; OpenSSL is a dependency | A02 malformed/63-byte/64-byte invalid signatures; A17 real verification followed by key-file swap; A24 invalid/missing key; A25 missing/timeout verifier fails without reservation or fallback. P trusted-key wrong-profile rejection and cross-language vectors. |
| `_consume_verified_in_transaction`: active transaction, one pin row/hash, epoch, check-time expiry, revocation, spent uniqueness, insertion | Verified tuple and connection are private/trusted implementation state, not a second public verifier | A04 zero/duplicate/wrong pin; A15 exact expiry boundary with deterministic test clock; A23 private-helper no-transaction rejection; P/R positive, stale epoch, forged key, expiry, revocation, replay and eight-process races. No guarantee against directly calling private helpers with fabricated trusted state. |
| `consume`: validate before open; existing-only DB; owned commit/rollback | Legacy public claim API; caller owns subsequent effect/policy | Legacy signed provider route is the only static production caller. P/R legacy regression and URI cases; A25 backend failure does not create missing authority; A22 shows shared helper is not fixed-effect policy. Two-database claim-before-effect liveness loss remains. |
| `consume_in_transaction`: owner-active transaction; no implicit commit/rollback | Trusted caller owns BEGIN/effect/COMMIT/ROLLBACK | A09 invalid auth preserves caller work and transaction; A10 second provisional claim fails then outer rollback restores; A11 read-only connection cannot become writer; A12 guard precedes key access; R nested savepoint and stale WAL snapshot; P provisional visibility. |
| Helper misuse / omitted effect | Caller is trusted, not automatically forced honest by helper | **A21 retained counterexample:** caller can commit a claim without an effect; status rejects inconsistent history and request remains spent. Only the fixed fixture owns the full pair transaction. |
| `revoke`: existing-only store; duplicate entry | Operator mutation, not agent permission editing | A08 repeated revoke is idempotent/no dispatch; P pre/post-commit semantics; R waiting writer sees committed revocation and missing literal paths create no alternate files. Revocation behind admitted writer is not cancellation. |
| `set_epoch`: existing-only store; strictly increasing integer; rollback on rejection | Operator policy-state change | A07 equal/decreasing/boolean/fractional/string/null reject and preserve config; A16 writer sees newly committed epoch; R missing/literal paths. No rollback-resistant trusted epoch service is established. |
| `atomic.validate_fixed_request` / `request_effect` | Agent controls only strict envelope; operator owns DB/key/CLI/failpoint | P fixed op/destination/effect/body and UTF-8/input bounds; R multibyte/surrogate/SQL-looking data; A22 legacy-allowed body is rejected by fixed fixture with provisional claim rolled back. |
| Fixed SQLite transaction, PRAGMA and implicit rollback | One retained local DB and normal SQLite locking/durability | A13 real SQLite trigger-induced transaction rollback preserves original error/no pair, then valid execution; A14 real SQL trace orders FULL sync, BEGIN IMMEDIATE, claim, effect, COMMIT; P/R five crash points in DELETE/WAL, lost ack, races. No power-cut/inside-COMMIT exhaustive faults. |
| `atomic.status`: exact expected binding; missing/neither/partial/conflicting/valid state | Read-only provider observation; no execution authority | A19 invalid status binding leaves history empty; A20 invalid effect ID/destination/joint digest never repairs or rewrites; P/R missing DB, partial rows, conflict, truthful terminal recovery. INCOMPLETE is not permission to replay. |
| Fixed CLI `read_input` / `main` | Raw stdin untrusted; argv operator-owned | A03 malformed UTF-8/JSON/root/envelope/duplicate/oversize input and command/argument/failpoint errors; valid request still works afterward. Backend exception cleanup tested in A25; all possible OS exceptions are not enumerated. |
| `sqlite_path.sqlite_file_uri`: ro/rw only; quoted ordinary filenames | Operator filesystem path, not an arbitrary URI | R `#`, `?`, literal `%23`, spaces, Unicode, exact file/table/inventory and no-create; R invalid mode injection; final separate reviewer additionally checked literal URI-looking names. Symlink/host manipulation remains outside model. |
| `sqlite_execution_gate.initialize/consume` and optional unsigned provider gate | Operator retains gate DB; legacy provider may deliberately omit gate | Existing execution-gate tests and R literal-path/no-create/replay cases. Optional ungated provider route is an explicit alternate route, not covered by the fixed signed-CLI guarantee. |
| Legacy `authorized-provider-fixture.main` | Signed claim API precedes a separate effect DB | Existing signed-route tests cover mutation/expiry/revocation/pin/epoch/race/missing state and preserved joint rollback. It is not the new atomic route. |
| `sqlite-provider-fixture.status` / signed status CLI | Operator path/key; operation ID/challenge untrusted | Existing signed-status tests cover versions, challenge/signature/binding, missing history, forged/ambiguous input; R literal/no-create; P lost-ack integration. Original status checks one effect row, not the atomic pair; provider-signed is not independent confirmation. |
| `verifyProviderStatus` / `verifyProviderHistory` | Caller supplies trusted pin and expected binding; envelope/history untrusted | Existing signed-status tests cover rejection, INCOMPLETE, PROVIDER_REPORTED, conflicting histories, challenge uniqueness and limits; P/R recovery retains rows unchanged. Host reducer labels alone do not enforce authorization. |
| `sqlite-status-witness` initialize/append/read | Operator pin/storage; signed canonical status untrusted | A26 adds shape/key/canonical/signature/size/argv failure vectors and byte-identical retained DB; existing tests cover valid append, forged slot, duplicate/ambiguous challenge and trust-root substitution; R literal/no-create read. Same-host witness is not independent or anti-rollback. |
| Legacy `sqlite-epoch-coordinator` initialize/claim/advance/inspect | Operator-controlled auxiliary SQLite store | Existing coordinator/crash/recovery/rollback tests cover claims, epochs and lost ack. **A27 retained limit:** missing claim store creates an empty file then rejects with no authority/schema; it does NOT have atomic-provider no-create semantics. No global/hostile-host guarantee. |

## Adjacent host authorization families — separate boundaries

- [Host boundary](boundary.mjs) `planAction/dispatchAction`: proposal snapshot,
  exact allow/approval/deny, missing/throwing/mismatched approval, optional consumer,
  post-await policy rechecks, missing callback, uncertain callback error. Covered
  by existing probes, mutation, policy-scope, guarded-tool and one-shot tests.
- [Guarded tool](guarded-tool.mjs) and [A2UI gate](a2ui-function-gate.mjs): trusted
  mapper/catalog/schema/callback configuration; frozen args, invocation claim,
  policy/approval failure and post-effect serialization uncertainty. Existing
  gate tests are included in full/action-boundary runs. These adapters do not
  authenticate people or make bypassed host callbacks impossible.
- [Process-local grants](one-shot-grants.mjs), [file grants](file-one-shot-grants.mjs),
  file authority/dispatch ledger, epoch anchors: existing one-shot/file/inspection/
  rollback/coordinator test families retain replay, directory integrity and rollback
  controls. Same-identity administrator and filesystem replacement are not solved.
- [Python host subset](python_boundary.py): separate schema/canonical subset and
  approval/consumer/callback branches. Existing five Python-specific unit tests
  are now explicit in the unfiltered pilot full-regression job, in addition to
  existing cross-runtime vectors and the challenge workflow.
- Broader core brand, threshold/release, governance-policy and HTTP authorization
  have separate existing tests included by default full discovery. They were
  surfaced by filename/call-site search, not re-proven or comprehensively newly
  audited here. No claim to eliminate every repository/plugin authorization path.

## Actual CodeQL versus ordinary regression guards

[CodeQL workflow](../../.github/workflows/codeql.yml) is a local proposed change:
normal main/development `pull_request` and selected base pushes, preserved schedule,
no path filter and no `pull_request_target`. Two expected checks:
`CodeQL (javascript-typescript)` and `CodeQL (python)`. Both use `security-extended`,
interpreted build mode `none`, no dependency install/cache, and a resolved immutable
CodeQL Action v4 commit. Node20/Python3.12 setup is explicit; CodeQL Action itself
uses its supported Node24 runtime. Other action major refs remain mutable.

Runner-local analysis uses **read-only contents/actions token;
no security-events write scope; no Code Scanning upload**. `upload: never` is
intentional: deprecated `false` maps to failure-only in inspected v4 source.
Database and SARIF-artifact uploads are disabled; reports remain transient on the
runner and only sanitized aggregate status is logged. This does not populate
Security-tab alerts. Complete local evidence is kept separately for private review.
No repository settings/protection were changed to make a scanner pass.

[The SARIF review script](../../scripts/check-codeql-sarif.mjs) is NOT a scanner
or signed-provenance verifier. Its self-contained CodeQL metadata profile requires
nonempty runs/tool/invocations, explicit results, suite/language/artifact inventory,
valid consumed messages/references/arrays, successful execution metadata and an
explicit full-analysis mode. Null notification arrays reject rather than disappear.
Known JS parser/extraction diagnostics and Python SyntaxError extraction warnings
fail quality even at warning/note/none severity. Benign warnings remain visible and
allowed. Component-qualified descriptor resolution cannot borrow another pack's
severity. Externalized reports and nonempty severity override chains are unsupported
and fail closed; this is not a general-purpose complete SARIF-schema implementation.

The workflow explicitly disables pinned-Action diff-informed and overlay analysis.
The pinned Action (v4.39.3 `analyze.ts`) writes `incrementalMode` ONLY for
diff-informed/overlay runs, so a full analysis omits it: absent or `none` is full;
any other value, the `codeql-action/pr-diff-range` extension pack, or a CLI other
than the bundled 2.27.4 fails quality without dropping findings. Public status adds
only allowlisted enum `quality_reason_codes`. The historical artifact reports `diff-informed`:
its28 findings were NOT an exhaustive whole-candidate inventory. Scan metadata and
artifact presence are not extraction-completeness or authenticity proof. A forged
synthetic report can satisfy the format profile; original scanner command/database/
source/query provenance and human adjudication remain separate requirements.

Full findings remain available to the local reviewer without suppression or baseline
waivers. CI emits ONLY aggregate quality/counts; raw SARIF, full findings/flows and
private counterexamples are not uploaded as artifacts or printed to public logs.
Findings alone do not fail the quality-only exit-code gate. A green required scan
is NOT a vulnerability-clearance or scanner-authentication claim. Metadata and
[reporter/CI tests](../../test/codeql-security-workflow.test.js) plus
[metadata integrity cases](../../test/codeql-sarif-integrity.test.js) are targeted
and fully discovered; separate scanner/source/DB provenance and review are needed.
No actual Node20/Python3.12 result follows from these tests.

The previously inspected main-targeted JavaScript SARIF had nonzero findings and
an extraction error despite a successful job. It is preserved as a REAL negative
control: this quality gate rejects it. That baseline needs scoped adjudication;
the integrated author candidate delegates the truncated legacy CLI to the existing
canonical compiler and tests parsing/manifest output, without inventing missing
logic. Actual scanner extraction must still be verified from the fresh database. Detailed findings/triage remain in local review artifacts.

## Two skipped jobs and outstanding evidence

`live-registry-receipt` requires `workflow_dispatch`; `live-registry-integrity`
requires schedule or `workflow_dispatch`. Both were genuinely SKIPPED on PR469;
public-registry/package observations are not authorization or CodeQL tests. Their
read-only rehearsals passed. Do not force live jobs, supply registry credentials
or invoke publication to obtain a green badge. No scanner coverage follows from
those skips or from the ordinary security-baseline contract script.

Existing published cloud evidence is Node20.20.2/Python3.12.16, 28 pilot acceptance
passes and 1199 default Node passes. Local Node24 had 1200 because it additionally
discovers existing `test/consumer-types.mts`; no separate TypeScript type-check
was established. New candidate results must be recorded separately—old green
checks are not evidence about these local changes.

Remaining limits: trusted issuer/provider/path/schema/caller/time/retained state;
rollback and direct-admin bypass; per-DB rather than global one-use; check-time
rather than completion expiry; no remote exactly-once, production isolation,
formal implementation refinement, exhaustive fuzzing, partitions or physical
outcome proof. Manual outcome mapping is bounded evidence, not a universal
“cannot bypass” proof. No public update until separate reviewer clearance and
parent authorization; leave draft and do not merge/deploy.


## Fixed local observer and enforcement boundaries

The project-owned opt-in local effect-observation adapter accepts only the actual
harness's literal HTTP127.0.0.1 observer URL, explicit decimal port, /invoke/32hex
nonce and48hex synthetic token. Values are snapshotted before approval reads;
redirects are errors. Invalid callback configuration is rejected before dispatch.
This is a fixed self-test fixture, NOT generic network-provider confinement,
production caller identity or outside-witness credit. See
[callback regression tests](../../test/action-observed-callback-confinement.test.js).

Descriptor-pinned reads and cooperative nontruncating registry appends retain
trusted owner/parent namespace assumptions. Registry prefix reads now have a
snapshot-sized read cap and reject detected growth before append; same-owner inode
rewrites/rollback and noncooperating administrative mutation are not eliminated.

Workflow YAML does not itself require checks. Repository administration must add
required statuses after verifying real job names. App-binding prevents another app
satisfying the context, NOT a malicious workflow edit reusing the same job name;
trusted workflow review, repository administration and runner/tool integrity remain
assumptions. No branch protection is changed by this source patch.


## Explicit no-debug and per-file extraction gates

A fixed-output guard must pass immediately BEFORE CodeQL init. It fails the job
(not a skipped-success context) if runner/step/CodeQL debug modes are enabled or
ambiguous. The pinned upstream Action's supported debug post-action can upload raw
SARIF/databases/logs despite upload:never; debug:false alone does not disable runner
debug. Combined-SARIF debug overrides are also rejected. This is a disclosure policy
for a supported debugging feature, not an upstream vulnerability or an observed leak.
Trusted workflow/admin/runner control remains required; no universal log-secrecy claim.

After actual analysis, the exact init output CLI and explicit database root execute
the committed table queries. The comparator requires positive TopLevel/Module roots
for EVERY tracked JS/TS/Python file, including all four authored report scripts that
previously lost ASTs. Missing, zero, duplicate, malformed or unavailable inventories
fail; extras such as HTML/Actions are not mistaken for tracked language roots. Only
bounded aggregate counts/status leave the step. Raw rows/paths/child stdout/stderr
stay transient; no raw artifact/database upload is configured. This is presence,
not complete semantics, vulnerability absence or authenticated scanner evidence.
Actual cloud producer metadata and AST results must still be observed, never restamped.


The governance-stream HTTP boundary now returns only a finite allowlist of public
protocol messages or stable codes. Unknown reader/evaluation errors use a generic
failure; malformed JSON no longer echoes parser detail. Dynamic duplicate/transition/
unsupported-protocol suffixes are intentionally reduced to codes. Before-header
HTTP status and after-header NDJSON terminal error behavior are tested separately.
This narrows error-detail API output; core session/auth/policy decisions are unchanged.
Synthetic no-detail regressions do not establish a preexisting remote secret exploit,
and do not claim resistance to malicious code/admin or arbitrary response contents.
