# ĀML separates transcript integrity, replay, signature, and trust

ĀML governance transcripts can now be signed with Ed25519 after they pass their own hash-chain and deterministic-replay verification.

This adds a new layer to the evidence model without pretending that every cryptographically valid signature is automatically trustworthy.

A signed transcript can now answer four separate questions:

1. Was the transcript structurally altered?
2. Do the recorded governance outputs reproduce from the recorded inputs?
3. Does the Ed25519 signature verify over the exact transcript?
4. Is the signing key independently trusted for the claimed signer and scope?

The reference verifier keeps these answers separate as `transcript_valid`, `replay_valid`, `signature_valid`, and `trusted_key`.

That distinction matters because a self-contained public key can prove cryptographic possession but cannot establish identity or authorization by itself.

## Commands

Sign a transcript:

```bash
aml-governance-transcript-sign transcript.json --key signer-private.pem > signed-transcript.json
```

Verify the mathematics:

```bash
aml-governance-transcript-signature-verify signed-transcript.json
```

Require a separately trusted key fingerprint:

```bash
aml-governance-transcript-signature-verify signed-transcript.json \
  --trusted-fingerprint <sha256-fingerprint> \
  --require-trusted-key
```

## What this creates

The architecture now has a progression from live decision to portable evidence:

```text
generated UI
   -> live governance decision
   -> continuous governance stream
   -> hash-chained replayable transcript
   -> Ed25519-signed transcript
   -> explicit external trust decision
```

Each layer adds a specific property rather than using one vague “verified” label for everything.

## Claim boundary

Generic transcript signing does not create official ĀRU authorization, independent validation, certification, or external adoption. The repository does not contain the production private ĀRU signing key. A verifier must establish signer identity and authorization through an independently trusted key or authorization mechanism.

This is a shipped technical milestone in the ĀML research prototype, not a standards-body or market-adoption claim.
