# ĀML Meaning Manifest

**Status: preview implementation; experimental protocol surface, not a ratified standard**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## From one meaning hash to a project meaning lock

A Meaning Fingerprint identifies the canonical Abstract Meaning Tree compiled from one ĀML source file.

A **Meaning Manifest** binds a whole declared set of ĀML files into one deterministic project root.

The experimental protocol identifiers are:

```text
aml-meaning-fingerprint/1
aml-meaning-manifest-material/1
aml-meaning-manifest/1
```

The manifest is designed for a narrow engineering question:

> Did any locked ĀML file's compiled meaning change, disappear, or get replaced by a different file set?

## Generate a manifest

```bash
aml-meaning manifest \
  ui/home.aml \
  ui/checkout.aml \
  ui/account.aml \
  > aml-meaning-lock.json
```

Paths are normalized into portable project-relative POSIX paths and sorted before hashing.

A manifest looks like:

```json
{
  "protocol": "aml-meaning-manifest/1",
  "version": "1.0",
  "algorithm": "sha256",
  "material_protocol": "aml-meaning-manifest-material/1",
  "fingerprint_protocol": "aml-meaning-fingerprint/1",
  "file_count": 3,
  "files": [
    {
      "path": "ui/account.aml",
      "fingerprint": "…",
      "amt_version": "1.0"
    }
  ],
  "root_sha256": "…"
}
```

The aggregate root binds the sorted file path, each file's Meaning Fingerprint, and the AMT version.

## Verify it

```bash
aml-meaning verify-manifest aml-meaning-lock.json
```

Verification requires the exact declared source set. It rejects:

- a file whose compiled AMT fingerprint changed;
- a missing file;
- an extra supplied file;
- duplicate manifest paths;
- unsorted manifest paths;
- unsafe absolute or parent-traversal paths;
- malformed fingerprints or root hashes;
- a manifest root that does not match its declared entries.

## Put it in GitHub Actions

Commit the lock file, then add:

```yaml
- uses: aruintelligence/aml-core/actions/meaning-manifest@main
  with:
    manifest-file: aml-meaning-lock.json
```

A text-only reformat that preserves every AMT keeps the manifest valid. A declared meaning change invalidates the relevant file fingerprint and therefore the project root.

## Why not just hash the directory?

A directory hash answers whether bytes changed.

A Meaning Manifest deliberately sits one layer later. It first compiles each ĀML source into its AMT and fingerprints that meaning material. Comments and whitespace can change without invalidating the lock. Meaning-bearing AMT changes cannot.

That makes the manifest useful for meaning-preserving refactors, generated-interface pipelines, release review, reproducible policy artifacts, and any workflow where raw line churn is less important than whether the declared interface meaning changed.

## Fingerprinting does not execute policy

Meaning identity stops at:

```text
source → lexer → parser → Abstract Meaning Tree
```

It does not execute render policy, produce HTML, or evaluate runtime context. Those are separate accountability layers with their own evidence.

This separation is intentional: a policy failure must not prevent a team from computing the identity of the AMT it was asked to evaluate.

## Evidence boundary

A valid Meaning Manifest does **not** prove that the application is safe, ethical, truthful, accessible, legally compliant, or behaviorally identical in every runtime.

It proves a smaller claim: under the declared versioned material contracts, the exact locked source set still compiles to the same canonical ĀML AMT fingerprints and aggregate project root.

That is enough to make "meaning did not change" a machine-checkable build assertion instead of a review comment.
