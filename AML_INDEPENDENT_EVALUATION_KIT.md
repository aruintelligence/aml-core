# Independent evaluation kit — action boundary

**Target:** `aruintelligence/aml-core` baseline `79a24ba96820a4ca974bcba30b797bf35dd7abc7`; evaluate the work branch PR separately once its exact commit is pinned. The already published [action-boundary reproduction](reproduction/action-boundary/REPRODUCE.md) pins a distinct release checkpoint and is the canonical path for its 508 indexed receipts. Do not mix those artifact counts with this branch's tests.

Requirements: Node 22+, Python 3.12+, Perl with core modules and OpenSSL for the full reproduction; no provider credentials or production access. A 15-minute goal is a usability target, not a measured external result.

```sh
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
git checkout 79a24ba96820a4ca974bcba30b797bf35dd7abc7
node pilots/action-boundary/boundary.test.mjs
node pilots/action-boundary/vectors.test.mjs
python3 pilots/action-boundary/verify_vectors.py
bash reproduction/action-boundary/reproduce.sh
```

The first three commands exercise digest binding, positive/negative dispatch, six exact Python vectors and a tamper case. The full script checks the pinned release artifacts and manifest. For the branch hardening, check out the PR head commit and run `node --test test/action-boundary-file-grant.test.js test/canonical-json-strictness.test.js test/browser-packet-json-integrity.test.js`, `node scripts/check-action-authorization-model.mjs`, and `npm test`.

Use `AML_VERIFICATION_RESULTS_TEMPLATE.md` to publish actual observations. The JS and Python adapters shipped by this repository are project-maintained; running them yourself may earn an independent reproduction (E3) if independently documented, but does not make them independent implementations (E4). A fresh implementation challenge is in `AML_ENGINEERING_CHALLENGE.md` and existing issue #171. Its runner compares self-reported adapter output on published cases; a pass alone does not prove that a callback was guarded or that the implementation is independent. Inspect implementation source and observe an independently instrumented local side effect before making either claim.

Trust assumptions: host controls policy and callbacks, authenticates consent, maps real targets, preserves grant state, and routes every effect through the guard. Digests detect byte changes but do not authenticate these assumptions. A returned callback does not prove provider acceptance or completion. Do not use example `.test` destinations for live operations.

For a stronger local callback observation, run the separate [experimental observed challenge](AML_OBSERVED_ACTION_CHALLENGE.md). Its loopback server counts actual adapter requests, while the legacy challenge only checks adapter-reported counts. Neither challenge alone proves internal policy causality, external provider completion, or E4 independence.
