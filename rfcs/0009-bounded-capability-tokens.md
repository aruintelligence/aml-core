# RFC 0009 — Bounded Capability Tokens and Replay Resistance

Status: Draft

## Abstract

This RFC defines signed, audience-bound capability tokens and replay-resistant AML wire metadata for multi-agent and cross-system execution.

## Capability tokens

An `aml-capability-token/1` binds:

- issuer
- optional subject
- optional audience
- a finite set of capabilities
- optional issue/expiry times
- optional nonce
- Ed25519 public-key fingerprint
- detached signature over the AML canonical JSON body

A verifier MAY additionally require an expected audience, a required capability, and a current time.

Tokens MUST fail verification when:

- the signature or fingerprint is invalid;
- the requested capability is absent;
- the audience does not match when one is required;
- the token is expired.

## Principle of least authority

AML capability tokens are intended to let an agent or application hold only the authority it needs. Examples:

- propose an interface but not publish policy;
- request policy evaluation but not bypass it;
- produce a receipt but not alter a transparency log;
- inspect View Meaning data but not access unrelated private claims.

## Replay resistance

`aml-wire/1` envelopes may carry:

- `session_id`
- `nonce`
- `issued_at`
- `expires_at`

A replay-aware receiver should reject a repeated `(session_id, nonce)` pair and expired envelopes.

The current reference replay guard is in-memory and therefore demonstrates protocol semantics, not a production distributed replay database. Production implementations must persist or otherwise coordinate replay state according to their threat model.

## Security considerations

A valid capability signature proves key possession and payload integrity. It does not establish that the issuer was authorized by a human, organization, law, or policy. Capability-token trust should be evaluated together with trust delegation, policy passports, revocation mechanisms, and local authorization rules.
