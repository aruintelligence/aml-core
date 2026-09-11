# Signed ĀML governance transcripts

Replayable governance transcripts can prove internal integrity and behavioral reproducibility. Ed25519 signatures add a separate question: which cryptographic key signed the exact transcript artifact?

Protocol:

```text
aml-signed-governance-stream-transcript/1
```

## Sign a verified transcript

The signing command refuses to sign a transcript that fails hash-chain or deterministic-replay verification.

```bash
aml-governance-transcript-sign transcript.json \
  --key signer-private.pem \
  --key-id evaluator-2026-01 \
  --signer "Example Evaluator" \
  --signed-at 2026-09-10T00:00:00.000Z \
  > signed-transcript.json
```

The private key must be Ed25519. It is read locally and is not written into the output.

The signed artifact includes the public key, SHA-256 fingerprint of its SPKI representation, key id, signature, optional signer label, timestamp label, and scope.

## Verify the signature

```bash
aml-governance-transcript-signature-verify signed-transcript.json
```

This checks:

- embedded transcript hash chain;
- deterministic transcript replay;
- public-key fingerprint consistency;
- Ed25519 signature validity.

## Add an explicit trust decision

A mathematically valid signature only proves possession of the matching private key. It does not prove that the key belongs to a person or organization you trust.

To require a supplied fingerprint:

```bash
aml-governance-transcript-signature-verify signed-transcript.json \
  --trusted-fingerprint <64-hex-sha256-fingerprint> \
  --require-trusted-key
```

Multiple `--trusted-fingerprint` arguments may be supplied.

The verifier deliberately reports `signature_valid` separately from `trusted_key`.

## Important trust boundary

There are four distinct questions:

1. **Transcript integrity:** was the transcript altered without rebuilding its chain?
2. **Replay validity:** do the recorded outputs follow from the recorded inputs in this runtime?
3. **Signature validity:** was this exact transcript signed by the private key corresponding to the embedded public key?
4. **Trust:** does the verifier independently recognize that key as authorized for the claimed signer/scope?

ĀML does not collapse these into one boolean claim.

Embedding a public key in a signed artifact is useful for self-contained cryptographic verification, but it is not a trust root. Trust requires an independently obtained fingerprint, key registry, authorization credential, or other out-of-band trust decision.

## Official ĀRU identity is separate

The existence of generic transcript-signing support does not make a transcript officially issued, endorsed, certified, or authorized by ĀRU Intelligence Inc. Official identity must be checked through the applicable official trust roots and authorization mechanisms. The repository does not contain the production private signing key.

## Evidence boundary

The implementation and tests here are project-controlled engineering evidence. Signing support does not turn project evidence into independent evidence. An external signer must still establish independence, identity, scope, and public evidence separately.
