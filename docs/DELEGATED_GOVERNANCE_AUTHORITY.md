# Delegated governance authority

ĀML can authorize protected live policy transitions through a chain of cryptographically authenticated trust delegations rather than requiring every operational signing key to appear directly in a verifier trust list.

## Why

A production governance root should not need to sign every policy change itself. A root can delegate a narrowly named capability to an operational key, and that key can delegate onward while preserving signed key continuity.

The existing signed trust-delegation protocol is used as the authority chain:

```text
aml-trust-delegation/2
```

For live governance mutation, every link must delegate the exact capability required by the verifier, normally:

```text
governance-policy-transition
```

## Verification

A policy-transition signature may include `delegation_chain`.

Delegated authority is accepted only when the verifier explicitly sets:

```json
{
  "allow_delegated_authority": true,
  "trusted_fingerprints": ["<root fingerprint>"],
  "required_scope": "governance-policy-transition"
}
```

The verifier then requires:

- the first delegation issuer key to be in the supplied root trust set;
- every delegation signature to verify;
- issuer/delegate names and key fingerprints to remain continuous across the chain;
- every link to carry the required capability;
- the final delegated key to equal the key that signed the exact policy transition;
- no issuer, intermediate, or leaf key to appear in the supplied revocation set;
- configured time/expiry checks to pass;
- the policy-transition signature itself to remain valid and bound to the exact stream, epoch, prior-policy hash, and requested update.

Delegation is disabled by default. Existing direct-trust behavior remains unchanged.

## Security boundary

A valid delegation chain proves cryptographic continuity from a verifier-selected root key to the leaf signing key under the declared capability. It does not establish legal identity, employment status, organizational approval, regulatory authority, certification, independent validation, or official ĀRU authorization unless those properties are established separately.

The verifier remains responsible for root trust, revocation input, time input, scope selection, and threshold policy.
