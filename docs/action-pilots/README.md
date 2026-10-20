# Controlled public page pilots

These ten pages are project-controlled fixtures hosted on GitHub Pages. Each
before page contains one intentional contact link, `#contact-action`, and one
redundant link, `#redundant-contact`, pointing to the same public issue path with
the same action label. The declared policy for this cohort is to suppress only
the redundant element and preserve the intentional link byte for byte.

The source manifest is
[`pilots/action-boundary/controlled-sites.json`](../../pilots/action-boundary/controlled-sites.json).
Regenerate the initial state with:

```sh
node scripts/build-controlled-pilot-pages.mjs --check-before
```

These pages are real public browser targets, but their content and duplicate
labels are entirely project-authored. Ten URLs on one controlled site are ten
page pilots, not ten unrelated organizations or independent validations. The
before source checkpoint is
[`877a8f8`](https://github.com/aruintelligence/aml-core/commit/877a8f8d64adf2d44c27dda73f1efe9f88d60418).
The after pages remove only `#redundant-contact`; the other HTML is byte for
byte identical. The host-owned render gate validates that exact change, binds
the before and after source hashes and the declared labels into the proposal,
requires matching host approval, and writes the after files only through the
frozen callback. Reproduce the ten dispatch receipts with:

```sh
node scripts/dispatch-controlled-pilot-pages.mjs --check
```

The [observed pilot report](../../publications/ACTION_BOUNDARY_CONTROLLED_PILOTS.md)
links ten before and after live page pairs, twenty browser screenshots, twenty
serialized DOM files, the browser observations, and ten paired SHA-256 receipts.
The contact path is a public issue URL; these fixtures do not submit any issue.
