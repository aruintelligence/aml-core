# PITCH — Can your runtime disagree with AML?

ĀML has a deliberately narrow interoperability challenge.

You do **not** need to implement the AML language.
You do **not** need to trust our JavaScript verifier.
You do **not** need to agree with our result.

Implement one public contract:

```text
aml-witness-bundle/1
```

Then expose:

```text
your-verifier --now <timestamp> bundle.json
```

returning:

```json
{"valid":true,"reason":"..."}
```

Run the black-box harness:

```bash
node scripts/run-verifier-conformance.mjs -- your-verifier
```

If it passes, publish the result.
If it fails, publish why.
If your implementation finds an ambiguity, open it.

Start here:
https://github.com/aruintelligence/aml-core/blob/main/docs/EXTERNAL_VERIFIER_10_MINUTES.md

Submit evidence:
https://github.com/aruintelligence/aml-core/issues/17

**Ask:** implement it without importing our verifier, deliberately mutate the artifact, and show us what your runtime says.

Status: PITCH. No external reproduction is claimed by this post.
