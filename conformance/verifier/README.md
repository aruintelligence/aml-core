# Verifier conformance target

**SHIPPED prototype target.**

This directory exists so an outside implementation can test one narrow question:

> Can your verifier accept the canonical AML witness bundle and reject bound mutations without importing AML reference-verifier code?

Start with:

- `manifest.json`
- `../../protocol/aml-verifier-cli.md`
- `../../independent/python/witness-vector.json`

Then publish your result as `aml-verification-report/1` and link it from GitHub Issue #17.

Negative results are welcome. If your implementation disagrees with JavaScript, Python, Go, browser, worker, or HTTP verification, publish the disagreement instead of adapting your output to hide it.

This target is project-defined compatibility tooling. It is not a ratified industry standard or certification program.
