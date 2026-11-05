# Controlled local provider recovery protocol (experimental)

This fixture exercises one narrow uncertainty case from `AML_EXECUTION_INTEGRITY_SPEC.md`: a one-use grant is consumed, the host initiates a request, a separate local provider process writes a durable effect marker, then exits without returning an acknowledgment. The host records `outcome_uncertain`; it must not label the effect failed or completed from its missing response. A new recovery process reads the provider-owned marker and reports `provider_reported_completed` for the matching operation ID and request digest. It does not call the provider write path.

Evidence levels: the initial host knows only grant consumption, request initiation, and transport failure. The recovery process separately reads a record written by the controlled provider process, so it can say the **fixture provider reports** the operation was recorded. This is not independent confirmation, a cryptographic attestation, a real external provider, or a production crash-consistent journal. A same-OS-identity attacker could edit the fixture files. No automatic retry is permitted when a response is lost and provider idempotency is unverified.

Expected negative cases: failure before provider write leaves zero effect markers and an uncertain host result until reconciliation establishes the fixture has no record; replay of the consumed grant blocks; a mismatched request digest cannot be reconciled as completion. The fixture uses exclusive creation and file and directory sync as a local demonstration, without claiming power-loss or network-filesystem guarantees.

Run from repository root:

```sh
node pilots/action-boundary/local-provider-recovery.mjs lost_ack
node pilots/action-boundary/local-provider-recovery.mjs before_write
node --test test/action-boundary-local-provider-recovery.test.js
```

The provider worker recomputes SHA-256 from the exact request bytes received as a command argument and writes that request and digest to a private temporary marker. Its process exits with a nonzero code after the marker sync in `lost_ack`. A second worker invocation reads the marker without entering the effect-writing path. The host orchestration process itself does **not** crash or persist its event log; its state reducer is in memory. Thus this is provider-worker restart and separately observed fixture storage, not completed host crash recovery. An absent marker after `before_write` is not generic proof that a real provider did nothing.

## Host process restart extension

`local-host-restart-worker.mjs` writes a host event snapshot with file and directory sync after each transition, consumes the one-use grant, records request initiation, invokes the separate fixture provider, and exits with code 77 before recording any provider acknowledgment. A **new host process** replays the journal through the existing state reducer, marks the missing response uncertain, checks that the grant is spent, and queries the provider-owned marker without invoking the effect-writing path. A matching marker permits the limited `completed` provider-report state; an absent marker remains uncertain. A changed request body in the journal fails recovery before any further provider call.

Run `node --test test/action-boundary-local-host-restart.test.js`. This exercises process termination after a child result, not a forced kill at every instruction or a power cut. The journal has no signature, MAC, external anchor, atomic multi-host transaction, or rollback detection. A same-identity attacker can replace the journal and marker together. It is a fault fixture, not a production execution protocol or independent confirmation.
