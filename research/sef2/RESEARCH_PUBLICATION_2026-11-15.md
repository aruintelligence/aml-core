# ĀML SEF2 — Independent Effect Authority: Research Publication

**ĀRU Intelligence Inc. | 15 November 2026 | Research preview — NOT production certified**

## Abstract

The SEF2 research implementation separates synthetic effect execution from durable
operation reservations and signed policy checkpoints. The primary safety objective
is to prevent a previously reserved operation from being applied again after the
effect database is rolled back. A separate Linux UID owns the reservation database
and exposes a peer-credential-checked Unix socket. An authorized effect process
cannot directly read or write that database in the disposable Linux test.

## Demonstrated mechanisms

1. Strict, canonical synthetic effects with bounded identifiers and values.
2. Monotonic policy floors and pinned Ed25519 checkpoint verification.
3. Durable reservation-before-effect ordering, with an intentional availability
   tradeoff: a crash between the two commits may strand the operation.
4. Read-only recovery classification: COMMITTED, STRANDED, ABSENT, CONFLICT,
   UNKNOWN. No classification authorizes retry.
5. Linux SO_PEERCRED checks, bounded socket request sizes, and read timeouts.
6. Fail-closed startup and runtime handling of missing reservation databases;
   an active process pins database file identity to detect straightforward replacement.
7. Regression tests for rollback, replay, malformed requests, peer denial,
   restart, missing files, and database replacement.

## Evidence and limitations

The previously verified SEF2 CI run at
https://github.com/aruintelligence/aml-core/actions/runs/43740981056 passed.
Subsequent CI at
https://github.com/aruintelligence/aml-core/actions/runs/43741417684
reported 553 tests with one test-harness exception mismatch, corrected in a
following commit; the correction requires a fresh successful run.

This is **synthetic SQLite effect evidence**, not proof of external real-world
execution, commercial-grade isolation, or a production authorization service.
SQLite databases and file metadata remain susceptible to privileged rollback,
administrative compromise, filesystem races, and coordinated restoration.
The independent reservation store must be administered under an actually
separate trust boundary. Peer UID authentication does not protect against
compromise of the allowed UID. Socket timeouts alone do not bound the number
of concurrent threads. A successful reservation followed by a crash may remain
permanently stranded. The current classifier does not resolve that ambiguity.

## Required before production release

- Reproducible end-to-end deployment under independently controlled identities,
  with protected key material and explicit bootstrap/recovery runbooks.
- Resource limits, socket lifecycle hardening, and denial-of-service testing.
- Independently anchored anti-rollback evidence for both reservation and
  checkpoint state, with documented assumptions and recovery procedures.
- Threat-model review, adversarial evaluation by a separate party, and
  operational observability with privacy-preserving audit receipts.
- Versioned artifacts, software bill of materials, dependency pinning,
  signed provenance, upgrade and rollback testing, and user documentation.

## Publication policy

This document describes a **research prototype**, not an assurance claim.
Do not advertise SEF2 as unbreakable, formally verified, independently certified,
or ready to protect real customer assets without additional evidence.

Copyright © 2026 ĀRU Intelligence Inc.
