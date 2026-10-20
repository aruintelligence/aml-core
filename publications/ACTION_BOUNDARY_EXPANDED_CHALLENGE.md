# Expanded action boundary challenge: 100 inspectable cases

**Status:** Project-authored fixtures and simulated callbacks. This challenge extends the original [13-case boundary challenge](ACTION_BOUNDARY_CHALLENGE.md); it does not replace it or constitute an outside verification.

The [100 exact cases](../conformance/action-boundary-expanded-cases.json) each publish a proposal, a host policy, the scripted host approval/callback behavior, an expected plan and dispatch receipt, the callback count, the exact executed proposal or `null`, and a reference to the [evidence receipt schema](../protocol/action-boundary-evidence-receipt.schema.json). The [100 JSONL evidence receipts](../conformance/action-boundary-expanded-receipts.jsonl) repeat the full declared evidence and add canonical SHA-256 digests of the input proposal, initial policy, and complete receipt body. These are **simulated test receipts**, not live-site receipts or authenticated logs.

Cases span mail, record reads and writes, payment requests, deletion, HTTP requests, and UI rendering. The matrices include reordered keys, changed payload, changed declared resource, changed tool/effect, callback uncertainty, duplicate rules, malformed input, invalid policy, and near-match rules. Approval-required cases also include missing/erroring approval, policy revocation while awaiting approval, and stale metadata. Specific adversarial cases inject BCC, change a `functionCallId`, replay an identical ID, mutate caller state while awaiting, and change an HTTP URL argument.

## Reproduce all 100

At a pinned checkout, with Node.js 22+ and Python 3.12+:

```bash
node scripts/build-action-boundary-expanded.mjs --check
node scripts/verify-action-boundary-expanded.mjs --check
node --test test/action-boundary-expanded.test.js
```

The first command regenerates the complete fixture corpus in memory and compares **exact file bytes** with the published copies. The second recomputes all 100 receipt hashes, compares each record with the case manifest, invokes the JavaScript boundary and the separate Python implementation for every case, and checks all plans, dispatch receipts, callback counts, and dispatched proposals. Python separately recomputes all 100 hashes with `hashlib` and its own JSON canonicalization:

```bash
python3 scripts/verify-action-boundary-expanded.py
```

The checked-in [machine report](../docs/action-boundary-expanded-report.json) includes corpus, receipt, schema, generator, and implementation source SHA-256 hashes. The `--check` verifier rejects a stale report. To reproduce the hash of a single record, parse one JSONL line, remove `receipt_sha256`, serialize the remaining object using the repository's [canonical JSON](../protocol/canonicalJson.js), UTF-8 encode it, and SHA-256 those bytes. The Python script performs this operation on **every** record without importing the JavaScript canonicalizer. Changing a proposal, policy, host fixture, expected outcome, or receipt field while leaving the original hash fails. Rehashing a changed receipt without changing its case fails the case comparison. Git commit history and pinned file hashes are the publication provenance; a self-computed SHA-256 is not an authenticated signature.

The canonical subset used for these cross-language fixtures contains JSON integers within the JavaScript safe range, BMP object keys, and Unicode scalar strings. JavaScript array-index object keys are enumerated numerically before other sorted keys. These checks do not establish compatibility for every possible JavaScript object or arbitrary JSON number.

## What the cases actually show

The plan uses `allow`, `requires_approval`, or `deny`; the host dispatch receipt records `blocked`, `dispatched`, or `unknown`. `dispatched` means the simulated callback returned, not that an outside effect completed. An invalid proposal, invalid policy, or ambiguous rule currently produces a **null plan proposal digest**, even though the evidence envelope separately hashes the input. The envelope binds the **declared initial policy** to the published test evidence; the underlying `aml-action-dispatch/1` receipt does not itself contain a policy hash.

Three counterexamples delimit the generic boundary:

| Case | Observed simulated behavior | Required additional host control |
|---|---|---|
| `mail-injected-bcc-fresh` | A changed proposal with fresh matching approval dispatches. | Validate every recipient, including BCC, against the mail tool's actual target policy. |
| `write-exact-call-id-replay` | The same payload and ID with fresh approval dispatch again. | Atomically consume a one-shot grant or invocation ID. |
| `http-argument-target-mismatch` | A declared allowed resource with a different argument URL dispatches. | Derive the actual destination from the tool arguments and compare it with the declared resource. |

See the repository's [mail target guard](../pilots/action-boundary/MAIL_TARGET_MANIFEST.md), [invocation claims](../pilots/action-boundary/A2UI_FUNCTION_GATE.md), and [target-boundary prototype](../pilots/action-boundary/TARGET_BINDING.md) for separate controls. This challenge does not claim those wrappers are automatically present around generic `dispatchAction` calls.

**Scope:** These are reproducible project-maintained fixtures, not independent parties, live web pilots, recipient authentication, policy authority, consent, effect completion, or proof that an unwrapped tool cannot act. A dishonest publisher can change both a record and its hash; pin the repository commit and inspect the sources and workflow run before relying on any result.
