# Wire validation-before-state invariant

ĀML wire envelopes must fail closed on malformed temporal metadata before replay state is mutated. Replay acceptance must require a valid `aml-wire/1` protocol envelope before nonce/session state is recorded.

This invariant is enforced by adversarial regression tests.
