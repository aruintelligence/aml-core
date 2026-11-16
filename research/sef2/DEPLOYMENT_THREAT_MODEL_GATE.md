# SEF2 independent reservation authority — deployment and threat-model gate

**Status: research-only. No production assurance claim.**

## Security objective and scope

The effect authority may apply a synthetic effect only after an independently
owned reservation has been durably recorded. The reservation owner must not
share administrative control, database credentials, or backup/restore authority
with the effect broker. The separate-UID Linux probe verifies a narrower,
operating-system-enforced file-access boundary, not independence of operators.

## Trust assumptions

- The reservation service's host, OS kernel, process UID, database, and backup
  mechanism are trustworthy and cannot be rolled back by the effect broker.
- The reservation database and WAL/SHM files reside in a directory that the
  broker cannot replace, rename, unlink, or traverse to a writable ancestor.
- The socket directory permissions allow connection but not socket replacement.
- The checkpoint signer and public-key pinning configuration are protected
  from unauthorized modification; signing keys are not present in the broker.
- The operator has a separately anchored record of committed reservation
  history before restoring backups. Local inode checks are insufficient.
- A successful reserve response can be lost; callers must treat ambiguity as
  **not authorized to retry**, not as evidence that reservation failed.

## Failure decisions

| Event | Required behavior | Operational action |
| --- | --- | --- |
| Reservation RPC unavailable, timeout, malformed reply | Deny effect | Investigate service health; do not retry blindly |
| Reservation succeeds, effect transaction crashes | Stranded operation | Quarantine and inspect; no automatic replay |
| Reservation DB missing or replaced during service lifetime | Deny | Stop service and investigate integrity |
| Effect record exists without matching reservation | Conflict | Freeze operation and investigate |
| Effect DB missing or unreadable | Unknown | No execution based on classifier |
| Reservation store restored to older valid contents | **Not reliably detected by current prototype** | Independently compare with external append-only anchor before restarting |
| Allowed UID compromised | Boundary lost for RPC requests | Rotate identities and investigate; do not claim isolation |
| Signing key compromised | Checkpoint authenticity lost | Revoke trust and re-enroll via independently approved recovery |

## Deployment checklist (all required)

1. Run the reservation service under a dedicated non-login OS identity, not the
   broker UID. Use an independently managed host or administrative boundary
   where the threat model requires protection against the broker administrator.
2. Create a private directory owned by the reservation identity; prohibit
   broker writes to the directory and all relevant ancestor directories.
3. Restrict socket filesystem access and SO_PEERCRED allowlist to the intended
   broker UID; do not infer identity from a user-supplied JSON field.
4. Secure SQLite database, journal, WAL, and SHM files together; set backup
   policy and verify that the broker cannot restore or replace them.
5. Keep a trusted, externally anchored monotonic reservation commitment or
   equivalent witness. **This capability is not implemented here.**
6. Pre-enroll checkpoint authorities, pin signing keys, and secure the durable
   high-water database independently of the effect broker.
7. Enforce process-level resource limits, service supervision, bounded logs,
   filesystem quotas, and alerting; socket handler limits alone are inadequate.
8. Test power-loss recovery, restore of stale snapshots, socket replacement,
   allowed-UID compromise, process restart, and key rotation in an isolated
   deployment before handling any real external effects.
9. Record an independent security review and verify all CI runs for the exact
   release commit, including the separate-UID Linux test.

## No-go conditions

**Do not deploy to protect real-world effects** when any actor in the threat
model can restore both effect and reservation stores to matching old snapshots,
or when external execution may occur without an independently verifiable
at-most-once effect boundary. A local SQLite fixture cannot establish either
property by itself.

Copyright © 2026 ĀRU Intelligence Inc.
