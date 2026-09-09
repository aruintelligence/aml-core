# ĀML Semantic Release Attestation Action

Verify an `aml-semantic-release-proof/1`, derive the ĀML in-toto semantic-release predicate, and publish a GitHub/Sigstore custom artifact attestation whose subject is the **actual proof JSON file**.

This Action intentionally does **not** create SLSA build provenance. It uses GitHub's custom-predicate artifact-attestation mode with the ĀML predicate type:

```text
https://aruintelligence.github.io/aml-core/predicates/semantic-release/v1.json
```

## Required workflow permissions

The calling job must grant the permissions required by GitHub artifact attestations:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  artifact-metadata: write
```

## Usage

For reproducible use, pin ĀML to an immutable commit or published release tag rather than `main`.

```yaml
jobs:
  attest-semantic-release:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
    steps:
      - uses: actions/checkout@v4

      - id: aml-attest
        uses: aruintelligence/aml-core/actions/semantic-release-attestation@main
        with:
          proof-file: release-proof.json

      - run: |
          echo "Attestation: ${{ steps.aml-attest.outputs.attestation-url }}"
          echo "AML signer: ${{ steps.aml-attest.outputs.signer }}"
          echo "Meaning state: ${{ steps.aml-attest.outputs.meaning-state-digest }}"
```

## One-command verification

The strongest normal verification path is:

```bash
aml-github-attestation release-proof.json --repo OWNER/REPOSITORY
```

The command invokes GitHub CLI without a shell and requires all of the following:

1. GitHub/Sigstore verifies an attestation for the exact proof-file bytes;
2. the attestation is scoped to the requested repository;
3. the signer repository is the requested repository;
4. the predicate type is exactly the ĀML semantic-release predicate URI;
5. self-hosted-runner attestations are rejected by default;
6. the locally recomputed SHA-256 of the proof file matches the verified in-toto subject digest;
7. the verified predicate exactly matches the predicate independently derived from the local proof;
8. the predicate's embedded `releaseProof` exactly matches the local proof;
9. the complete ĀML Semantic Release Proof verifies, including signed manifests, lineage, semantic roots, source snapshots, detailed diffs, proof hash, public-key fingerprint, and Ed25519 signature.

A caller can explicitly opt into self-hosted attestations with `--allow-self-hosted`. That is a conscious trust-policy change, not the default.

Optional stricter workflow pinning is available:

```bash
aml-github-attestation release-proof.json \
  --repo OWNER/REPOSITORY \
  --signer-workflow OWNER/REPOSITORY/.github/workflows/release.yml
```

Offline GitHub attestation bundles can be supplied with `--bundle`.

## Manual verification path

GitHub verification alone can be run with:

```bash
gh attestation verify release-proof.json \
  -R OWNER/REPOSITORY \
  --predicate-type https://aruintelligence.github.io/aml-core/predicates/semantic-release/v1.json \
  --signer-repo OWNER/REPOSITORY \
  --deny-self-hosted-runners \
  --format json
```

Then verify the ĀML proof itself:

```bash
aml-release-proof release-proof.json
```

GitHub documents that custom predicate contents are workflow-controlled data even after the attestation signature verifies. That is why `aml-github-attestation` does not stop at GitHub verification: it independently recomputes and verifies the ĀML predicate and nested semantic proof.

## Two subjects with different jobs

Do not conflate these:

- **GitHub artifact subject:** the exact `release-proof.json` bytes, bound through `actions/attest` `subject-path`.
- **ĀML meaning-state subject:** the virtual `aml-meaning-state:<release-id>` resource inside the locally derived ĀML in-toto statement, whose digest is the verified after-Meaning-Manifest semantic root.

The preparation metadata uses explicit `meaning_state_name` and `meaning_state_digest` fields so downstream tooling cannot mistake the virtual semantic state for the GitHub artifact subject.

## Two verification layers, two claims

1. **GitHub/Sigstore attestation:** the repository workflow produced an attestation binding the proof-file bytes to the supplied ĀML predicate.
2. **ĀML Semantic Release Proof:** the embedded signed semantic transition, manifests, lineage, roots, diffs, attribution, and proof material verify under the declared ĀML contracts.

Neither layer proves that declared meaning is objectively true, the release is safe/ethical/legal, the ĀML signer has institutional authority merely because a key verified, or the project satisfies SLSA. This is a custom in-toto predicate, not SLSA build provenance.

## Dependency pin

The composite Action pins the official `actions/attest` dependency to commit:

```text
1e69f48acb82d1966a394da916b4c1698aa569d6
```

That commit is the immutable `v4.2.2` release used when this integration was authored.
