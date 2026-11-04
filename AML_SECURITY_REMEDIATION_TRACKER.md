# Security remediation tracker

| ID | Priority | Owner / next action | State | Acceptance criterion |
| --- | --- | --- | --- | --- |
| A-01 partial file-store replay | P0 for pilot users | Maintainer: review branch and migration note | Implemented, awaiting PR review | Regression blocks re-issue and replay after spent-directory loss; CI passes. |
| A-02 inherited serialization hook / array method | P0 for canonicalizer | Maintainer: review compatibility and browser build | Implemented, awaiting PR review | Same valid JSON vector digests, no inherited hook or input-owned map call, full test pass. |
| A-03 whole-store rollback, multi-host atomicity | P0 before production | Host integration team: independently retained transactional claim/epoch | Open | Cross-host race, rollback, outage, crash and revocation test with externally retained evidence. |
| A-04 provider completion ambiguity | P0 before delivery claims | Provider adapter team: stateful idempotency and reconciliation | Open | Receipt distinguishes initiated/accepted/completed/confirmed/unknown with provider evidence. |
| A-05 deep/cyclic/oversize input budget | P1 | Protocol team: bounded depth/size traversal and deterministic failure vectors | Partial: cycles fail explicitly; guarded RangeError returns a blocked receipt | Cyclic or overflowing guarded arguments block with zero callback; proactive depth/size and proxy resource limits remain open. |
| A-06 target resolver and bypass routes | P1 | Integrating host: enumerate effectful paths | Open | Every effectful provider route mediated; negative bypass tests. |
| A-07 private evidence/logging | P1 | Security team: retention/redaction review | Open | No credentials/personal payload in default logs; access and retention tests. |
| A-08 external verification | P1 | Outside engineers | Open | Published independent PASS/FAIL/MIXED report tied to exact commit and vectors. |
