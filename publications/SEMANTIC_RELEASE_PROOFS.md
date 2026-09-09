# ĀML Semantic Release Proofs

**Status: preview implementation; experimental protocol surface, not a ratified standard**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## One artifact for a semantic release transition

A conventional release artifact can tell you which source files changed. An ĀML Semantic Release Proof is designed to answer a narrower, reproducible question:

> Between two signed ĀML project states, exactly which compiled meaning fingerprints changed, what did the detailed ĀML semantic diff report for changed files, who signed the proof, and is the signed semantic history intact?

The experimental protocol identifier is:

```text
aml-semantic-release-proof/1
```

The signed material is domain-separated as:

```text
aml-semantic-release-proof-material/1
```

## What is inside

A proof contains:

- the before Meaning Manifest;
- the before Meaning Manifest Ed25519 attestation;
- the after Meaning Manifest;
- the after Meaning Manifest Ed25519 attestation;
- the complete append-only Meaning Lineage ending in those two releases;
- the lineage head hash;
- before and after semantic project roots;
- an aggregate added / removed / changed / unchanged summary;
- one deterministic change record per path;
- source snapshots only where needed to independently recompute added, removed, or changed meaning;
- a detailed `semanticDiff()` report for each changed file;
- signer identity and generation time;
- a SHA-256 content identifier for the canonical proof material;
- an Ed25519 signature over that exact material.

Unchanged files do not need duplicate source snapshots. Their equality is represented by identical per-file Meaning Fingerprints in the two signed manifests.

## Verification stack

`verifySemanticReleaseProof()` does not trust the report fields. It independently verifies:

1. both Meaning Manifest internal roots;
2. both detached Meaning Manifest signatures;
3. the entire Meaning Lineage;
4. that the final two lineage entries exactly match the supplied before/after signed artifacts;
5. before/after root bindings;
6. the derived `semantic_changed` flag;
7. the exact path set represented by the two manifests;
8. every added/removed/changed source snapshot against its signed manifest fingerprint and AMT version;
9. every detailed changed-file semantic diff by recomputation;
10. the aggregate change summary;
11. the release-proof SHA-256;
12. the Ed25519 public-key fingerprint;
13. the Ed25519 signature over the full canonical proof material.

Only when the full stack agrees does the verifier return `verified: true` and expose the signer as authenticated attribution.

## CLI verification

A proof file can be checked without writing application code:

```bash
aml-release-proof release-proof.json
```

Exit codes:

- `0` — the full proof verifies;
- `1` — the artifact was parsed but verification failed;
- `2` — invocation, file, or JSON error.

## in-toto Statement v1 bridge

A fully verified Semantic Release Proof can be exported into a standard in-toto Statement v1 envelope:

```bash
aml-release-proof in-toto release-proof.json > semantic-release.intoto.json
aml-release-proof verify-in-toto semantic-release.intoto.json
```

The statement type is the standard in-toto URI:

```text
https://in-toto.io/Statement/v1
```

The predicate type is owned and published by ĀML:

```text
https://aruintelligence.github.io/aml-core/predicates/semantic-release/v1.json
```

The subject is the resulting `aml-meaning-state:<release-id>` resource, with its verified after-Meaning-Manifest root carried as the SHA-256 digest. The predicate embeds the complete signed `aml-semantic-release-proof/1` plus derived release, semantic, and authenticated attribution fields.

`verifyInTotoSemanticReleaseStatement()` does not trust the envelope's copied metadata. It re-verifies the embedded release proof, then recomputes the subject, before/after roots, semantic-change flag, lineage head, change summary, signer, generation time, public-key fingerprint reference, and proof hash.

This is deliberately **not** labeled SLSA build provenance. A Semantic Release Proof describes an ĀML semantic state transition; SLSA build provenance describes how a build produced an artifact. The in-toto Statement is the interoperability envelope, while the ĀML predicate defines the claim being carried.

## Semantic Release Gate — GitHub Action

A repository can make a verified semantic release proof a deployment prerequisite:

```yaml
- id: semantic-release
  uses: aruintelligence/aml-core/actions/semantic-release-proof@main
  with:
    proof-file: release-proof.json

- run: |
    echo "Signer: ${{ steps.semantic-release.outputs.signer }}"
    echo "Before: ${{ steps.semantic-release.outputs.before-root }}"
    echo "After: ${{ steps.semantic-release.outputs.after-root }}"
    echo "Changed paths: ${{ steps.semantic-release.outputs.changed }}"
```

The action exits nonzero unless the complete proof verifies. On success it exposes authenticated or recomputed values including the signer, release IDs, before/after semantic roots, lineage head, proof hash, semantic-change flag, and added/removed/changed/unchanged counts.

The action does not make a deployment decision by itself. It supplies a cryptographically verified semantic release state that a repository can combine with its own approval, testing, policy, and rollout requirements.

## Why source snapshots appear only for changed paths

The signed Meaning Manifests already bind the complete project path set and every file's AMT fingerprint. For an unchanged path, identical signed fingerprints are enough to establish equality under the Meaning Fingerprint contract.

For a changed path, a verifier needs the source material that produced each fingerprint to recompute the detailed semantic diff. The proof therefore carries before/after source snapshots only for changed paths, and one-side snapshots for added or removed paths.

This keeps the proof self-contained without unnecessarily duplicating the entire project source tree.

## Tamper behavior

The adversarial suite rewrites:

- detailed semantic-diff output;
- embedded changed source;
- change summaries;
- signer identity;
- generation time;
- semantic roots;
- lineage head;
- nested manifest attestations;
- historical lineage entries;
- the proof signature and public key;
- in-toto subject name/digest;
- in-toto predicate type;
- copied semantic and attribution metadata.

These mutations must cause verification to fail.

## Evidence boundary

A valid Semantic Release Proof establishes cryptographic integrity and reproducible consistency under the declared ĀML contracts. It can show that signed compiled meaning roots differ, which paths changed under those fingerprints, what the ĀML semantic-diff implementation recomputes from the embedded snapshots, who possessed the signing private key, and whether the embedded semantic lineage is intact.

An in-toto-wrapped proof carries those same project-defined claims in a standard attestation envelope. It does **not** transform them into SLSA provenance or prove that declared meaning is truthful, that a release is ethical or safe, that two arbitrary programs have identical runtime behavior, that the signer has institutional authority, that the software complies with law or regulation, or that ĀML is a ratified standard.

That boundary is intentional.
