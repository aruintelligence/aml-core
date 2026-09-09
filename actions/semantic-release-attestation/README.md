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

The normal verification path is:

```bash
aml-github-attestation release-proof.json --repo OWNER/REPOSITORY
```

It requires GitHub/Sigstore verification, exact repository and signer-repository binding, the exact ĀML predicate type, non-self-hosted attestation by default, exact local proof-file digest binding, exact predicate recomputation, exact embedded-proof equality, and complete nested ĀML Semantic Release Proof verification.

## Production release-key trust

A valid Semantic Release Proof proves possession of its embedded Ed25519 private key. It does **not** by itself establish that the key is an authorized release key. For production verification, supply an out-of-band trust policy:

```json
{
  "protocol": "aml-release-key-trust-policy/1",
  "policy_id": "production-release-keys",
  "trusted_keys": [
    {
      "public_key_sha256": "<64 lowercase hex characters from the approved release key>",
      "signer": "release-bot"
    }
  ]
}
```

Then verify all layers at once:

```bash
aml-github-attestation release-proof.json \
  --repo OWNER/REPOSITORY \
  --trust-policy release-key-policy.json
```

The trust policy is deliberately external to the proof and attestation. Embedding the trust root inside the object being verified would let an attacker replace both the release key and its claimed authorization. A policy entry can omit or set `signer` to `null` to trust the fingerprint regardless of the signed human-readable signer label.

A caller can explicitly opt into self-hosted attestations with `--allow-self-hosted`. That is a conscious trust-policy change, not the default. Optional stricter workflow pinning is available with `--signer-workflow`, and offline GitHub attestation bundles can be supplied with `--bundle`.

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

## Three verification layers, three claims

1. **GitHub/Sigstore attestation:** a qualifying GitHub workflow produced an attestation binding the proof-file bytes to the supplied ĀML predicate.
2. **ĀML Semantic Release Proof:** the embedded signed semantic transition, manifests, lineage, roots, diffs, attribution, and proof material verify under the declared ĀML contracts.
3. **External release-key trust policy:** the semantic proof was signed by a key fingerprint that the verifier explicitly chose to trust, optionally constrained to the signed signer label.

The third layer does not magically create institutional authority. It establishes authorization only relative to the externally supplied policy. The provenance of that policy remains the verifier's responsibility.

None of these layers proves that declared meaning is objectively true, the release is safe/ethical/legal, or the project satisfies SLSA. This remains a custom in-toto predicate, not SLSA build provenance.

## Dependency pin

The composite Action pins the official `actions/attest` dependency to commit:

```text
1e69f48acb82d1966a394da916b4c1698aa569d6
```

That commit is the immutable `v4.2.2` release used when this integration was authored.
