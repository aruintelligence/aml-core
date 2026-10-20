# Five implementations against 100 exact action cases

**Status:** Project-maintained interoperability evidence. These bindings are not independent external witnesses.

The [machine matrix](../docs/action-five-runtime-report.json) records the same proposal digest, plan decision, gate outcome, dispatch status, reason, and callback count for every one of the [100 published cases](../conformance/action-boundary-expanded-cases.json) across:

| Binding | JSON and SHA-256 path | Execution in the checked-in matrix |
|---|---|---|
| Existing JavaScript | Repository canonical JSON and Node crypto | Node |
| Existing Python | Python JSON and `hashlib` | Python |
| New Perl | `JSON::PP` and `Digest::SHA` | Perl |
| New Python/OpenSSL | Separate Python decision/canonicalization code and OpenSSL `dgst` | Python invoking OpenSSL |
| New WebCrypto | Browser-compatible ES module, `TextEncoder`, and `crypto.subtle.digest` | Node WebCrypto for the machine matrix |

For each case the runner also compares the **complete** plan and dispatch receipt, callback count, and frozen proposal handed to the simulated callback with the published expectation. The table's `gate_outcome` is `ALLOW` when the host callback was invoked and `SUPPRESS` when it was blocked: **29 ALLOW / 71 SUPPRESS in each binding**. A callback throw remains `execution_status: unknown`; ALLOW here means an invocation was attempted, not that an outside effect succeeded. The matrix contains each of the five observed compact outcomes and source SHA-256 values. No actual email, payment, database write, UI mutation, or HTTP request is performed.

```bash
node scripts/build-action-five-runtime-report.mjs --check
node --test test/action-five-runtime.test.js
```

The [browser runner](https://aruintelligence.github.io/aml-core/action-browser-matrix.html) loads an exact copy of the corpus, checks its whole-file SHA-256 before running it, and then evaluates all 100 cases in the browser using the same browser-compatible WebCrypto module. The checked-in matrix states its actual Node WebCrypto execution environment. A browser result is a separate, inspectable run and should be reported with its browser version and observed output, not inferred from the Node result.

The Perl and alternate Python implementations accept the published JSON subset. In particular, canonical object ordering puts JavaScript array-index keys before ordinary sorted keys. These implementations establish agreement on **these inputs**, not general equivalence for arbitrary objects, floating-point encodings, untrusted policy authority, or real side effects. They are all maintained inside this repository; the independent-party count remains zero until outside maintainers publish reproducible source and results.
