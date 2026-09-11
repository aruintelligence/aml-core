# Selective governance disclosure

ĀML can disclose selected governance-transcript entries without publishing every message body in the transcript.

The disclosure artifact commits to all transcript entry hashes with a Merkle root and carries inclusion proofs for only the selected entries.

## Generate

```bash
aml-governance-disclose transcript.json 1,4 > disclosure.json
```

## Verify

```bash
aml-governance-disclosure-verify disclosure.json \
  --expected-merkle-root <trusted-root> \
  --expected-transcript-root <trusted-transcript-root>
```

Protocol:

```text
aml-governance-selective-disclosure/1
```

The verifier checks each disclosed entry's canonical entry hash, its Merkle inclusion path, the disclosure commitment, and optional externally supplied roots.

## Privacy and trust boundary

This is selective disclosure, not zero-knowledge proof. It hides undisclosed message bodies but still reveals transcript entry count, selected indices, disclosed entries, the transcript root, and a Merkle commitment to all entry hashes.

A Merkle proof proves membership in a commitment. It does not prove who created the commitment. Authenticity requires the commitment or transcript root to be obtained from a trusted signed transcript, witness quorum, publication, or another authenticated channel.
