# Wire hardening note

ĀML wire envelopes must fail closed on malformed temporal metadata before replay state is mutated. The replay guard must accept only envelopes that pass the canonical `aml-wire/1` validator.

This note documents the security invariant enforced by the accompanying tests and runtime changes.
