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

## Verify through GitHub

Because the GitHub attestation subject is the actual proof file, consumers can use GitHub's artifact-attestation verification flow against that same file and require the ĀML custom predicate type:

```bash
gh attestation verify release-proof.json \
  -R OWNER/REPOSITORY \
  --predicate-type https://aruintelligence.github.io/aml-core/predicates/semantic-release/v1.json
```

The GitHub/Sigstore verification establishes the GitHub workflow identity and integrity of the custom attestation around that file. The embedded ĀML predicate should then be checked with the ĀML verifier as well:

```bash
aml-release-proof release-proof.json
```

For a locally exported ĀML in-toto statement:

```bash
aml-release-proof in-toto release-proof.json > semantic-release.intoto.json
aml-release-proof verify-in-toto semantic-release.intoto.json
```

## Two verification layers, two claims

1. **GitHub/Sigstore attestation:** the repository workflow produced an attestation binding the proof-file bytes to the supplied ĀML predicate.
2. **ĀML Semantic Release Proof:** the embedded signed semantic transition, manifests, lineage, roots, diffs, attribution, and proof material verify under the declared ĀML contracts.

Neither layer proves that declared meaning is objectively true, the release is safe/ethical/legal, the AML signer has institutional authority merely because a key verified, or the project satisfies SLSA. This is a custom in-toto predicate, not SLSA build provenance.

## Dependency pin

The composite Action pins the official `actions/attest` dependency to commit:

```text
1e69f48acb82d1966a394da916b4c1698aa569d6
```

That commit is the immutable `v4.2.2` release used when this integration was authored.
