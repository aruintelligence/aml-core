# ĀML package reproducibility

The repository generates a deterministic manifest of the files selected by `npm pack --dry-run`.

Each selected file is recorded with its path, byte size, and SHA-256 digest. Those records are combined into a package-content root digest. CI generates the manifest twice from the same checkout and rejects any mismatch.

`package-content-policy.json` also requires core consumer files and rejects obvious private-key / local credential filename patterns from the npm-selected package set.

This deliberately distinguishes two different claims:

- **project-controlled package content reproducibility:** the same checkout repeatedly yields the same file-content manifest;
- **external reproducible build evidence:** another party independently reproduces the same artifact or manifest.

Only the first is established by this workflow. It does not claim npm publication, registry-side provenance, external verification, certification, or immunity from every possible secret-leak pattern.
