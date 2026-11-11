# SEF/1 synthetic payables reference integration

Research profile only. This directory is a runnable vertical slice, not a
payment product, public protocol, or claim of novelty. It uses the existing
`aml-authorized-execution/1` signed authorization implementation at
`pilots/action-boundary/authorized_execution.py` without changing its wire
format. No external transaction is made.

## Run

Requirements: Linux with `bwrap`, Python 3.10+ with SQLite, and OpenSSL with
Ed25519 support. From the repository root:

```sh
python3 research/sef1/demo.py
python3 research/sef1/lab_test.py --report /tmp/sef1-results.json
python3 research/sef1/model.py
```

The demo returns a provider-reported synthetic effect, denial of exact replay,
and denial of changing the merchant after approval. The lab tests also retain
deliberately successful bypasses outside the confined agent boundary.
The focused workflow `.github/workflows/sef1-research-lab.yml` runs a
`--portable` mode on an Ubuntu runner without installing bubblewrap. It tests
authorization and crash/rollback behavior but explicitly skips the sandbox
isolation test. Run the default commands above on a Linux system with bubblewrap
before making any claim about confinement. The initial CI attempt to install
bubblewrap failed because the runner could not resolve Ubuntu package mirrors;
that failed run remains part of the experiment record.

## Integration contract

The untrusted agent can write a bounded JSON proposal to the inbox. The
trusted fixture is configured by its administrator with the issuer public key,
separate retained SQLite authority and provider paths, and exactly one
permitted effect: `payment:simulate`, destination `fixture:merchant-a`, USD
integer amount from 1 through 10,000 minor units. The agent never receives a
provider credential or a raw dispatch token. The service verifies the signed
authorization, exact request bytes, expiry, operation identity, revocation and
policy epoch before it commits a one-use claim and writes the synthetic effect.
The response is `PROVIDER_REPORTED`, `DENIED`, `UNCERTAIN`, or `INCOMPLETE`.
`PROVIDER_REPORTED` is a row in the fixture's provider database; it is not
independent confirmation of real provider acceptance or completion.

The `bwrap` launcher in `lab_test.py` makes the agent's root read-only,
exposes a writable inbox and read-only outbox, and masks the trusted directory.
This tests a **confined agent process** under a trusted kernel, launcher,
administrator and issuer. It does not isolate a hostile host administrator.
An agent launched outside that sandbox with the same UID can write the provider
database and forge a receipt. Never treat this lab deployment as independent
administration of the AI host.

## Required work for a real provider integration

1. Run authority and provider credentials in a separately administered domain;
   prohibit all alternate provider routes from the AI host and test them.
2. Retain replay and policy-epoch state independently of restorable host
   snapshots; test restoring *both* current stores.
3. Use provider-native idempotency keys and a provider status lookup whose
   attribution and finality are defined. Reconcile `UNCERTAIN` without an
   automatic retry of an irreversible effect.
4. Verify approval identity and consent in the policy authority, independently
   of the AI agent. Define clock trust and key custody/rotation.
5. Record externally witnessed evidence if dispute resistance is required;
   this prototype has no such witness.

The existing MIT license and published wire formats remain unchanged. Review
the counterexamples in `lab_test.py` and bounded exploration in `model.py`
before extending this prototype.
