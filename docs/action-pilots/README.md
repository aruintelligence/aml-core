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
before and after source checkpoints, browser screenshots and DOM hashes, and
host boundary receipts are published in a subsequent evidence package.
