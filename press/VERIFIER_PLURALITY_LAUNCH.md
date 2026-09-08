# The page does not get the last word

**Status: DRAFT public launch copy**

A single verifier can still be wrong.

ĀML now publishes prototype contracts for **multiple verifiers to check the same exact witness artifact and preserve disagreement instead of flattening it**.

Shipped:

- portable `aml-verification-report/1`
- machine-readable `aml-verifier-manifest/1`
- `aml-verification-quorum/1`
- browser / worker / HTTP / Python reference verification paths
- a public witness registry that currently says exactly what reality says: **0 external witnesses**

If three verifier reports target the same artifact hash, ĀML can show:

```text
verifier A: PASS
verifier B: FAIL — signature mismatch
verifier C: PASS
threshold: 2
threshold met: yes
unanimous: no
```

That disagreement remains visible.

Try the plurality demo:
https://aruintelligence.github.io/aml-core/quorum-demo.html

External challenge:
https://github.com/aruintelligence/aml-core/issues/17

**Ask:** implement verification outside `aml-core`, publish your report, mutate the artifact, and file what happens.

Claim boundary: verifier agreement is evidence of agreement over the same artifact under this prototype contract. It is not certification, identity proof, standards-body approval, or proof that declared AML inputs are objectively true.
