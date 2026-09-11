# Signed selective governance disclosure

ĀML can authenticate the compact commitment behind a selective governance disclosure without signing or publishing the full governance transcript.

A disclosure commitment contains only:

- the source transcript root;
- the source transcript entry count;
- the Merkle root committing to every transcript entry hash.

Protocol identifiers:

```text
aml-governance-disclosure-commitment/1
aml-signed-governance-disclosure-commitment/1
```

## Sign a disclosure commitment

```bash
aml-governance-disclosure-sign disclosure.json \
  --key witness-private.pem \
  --key-id witness-1 \
  --signer "Example witness"
```

## Verify disclosure against the signed commitment

```bash
aml-governance-disclosure-signed-verify \
  disclosure.json \
  signed-commitment.json \
  --trusted-fingerprints <sha256> \
  --require-trusted-key \
  --required-scope governance-disclosure-commitment
```

The verifier independently checks:

1. the Ed25519 signature over the commitment;
2. the public-key fingerprint;
3. verifier-supplied trust eligibility and revocation policy;
4. optional signer scope;
5. the selective disclosure's Merkle proofs against the signed Merkle root;
6. the source transcript root and source entry count against the signed commitment.

## Trust boundary

A valid signature proves possession of the corresponding private key. It does not establish a real-world identity by itself. An embedded public key is not a trust root. A verifier should obtain trusted fingerprints and revocation state through an independent channel.

Generic signing also does not grant official ĀRU authorization. Official ĀRU identity and trademark authorization remain governed by the repository's separate trust-root and authorization mechanisms.

This remains selective disclosure, not zero-knowledge proof: metadata described by the disclosure format is still revealed.
