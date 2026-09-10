# ĀML Implementation / Interoperability Report Template

Use this template to report an implementation, independent reproduction, or cross-runtime interoperability result.

PASS, FAIL, MIXED, and UNSUPPORTED results are all useful when the evidence is reproducible.

## 1. Report identity

- Report date/time (UTC):
- Reporter / organization:
- Public source URL:
- Public report URL:
- Maintained inside `aruintelligence/aml-core`? YES / NO
- Independence statement:

## 2. Implementation identity

- Implementation name:
- Language/runtime:
- Runtime/compiler version:
- Operating system / architecture:
- Exact implementation commit/tag:
- License:

## 3. AML target

- AML repository/release/commit used as specification reference:
- Public contract(s) implemented:
- Schema/vector versions:
- Claimed compatibility level, if any: Core / Accountable / Federated / Verifiable / Governed / none

Do not claim whole-language compatibility because one artifact contract passes.

## 4. Dependency boundary

For the behavior claimed as independently implemented:

- imports `aml-core` runtime internals? YES / NO
- executes `aml-core` CLI/API as the implementation? YES / NO
- wraps another AML verifier? YES / NO
- copies generated output rather than independently computing it? YES / NO
- external dependencies used:

Explain any shared code or generated artifacts.

## 5. Contracts tested

For each contract:

| Contract | Version | PASS / FAIL / MIXED / UNSUPPORTED | Evidence |
| --- | --- | --- | --- |
| | | | |

## 6. Canonical/golden vectors

- Vector source/path:
- Exact vector hash/version:
- Expected output:
- Actual output:
- Result:

Include raw output or a stable link when practical.

## 7. Negative and tamper tests

Document deliberately invalid cases. Examples include:

- changed declared purpose;
- changed decision;
- altered hash;
- altered signature;
- expired challenge;
- nonce/binding mismatch;
- invalid public key;
- unsupported contract version;
- replayed envelope where replay protection applies.

For each case, record expected rejection and actual behavior.

## 8. Cross-implementation exchange

If two implementations exchanged artifacts rather than only reading fixtures:

- producer implementation:
- consumer/verifier implementation:
- artifact/contract:
- producer command:
- consumer command:
- result:
- exact artifact hash:

If no live exchange occurred, say `NOT TESTED`.

## 9. Disagreements / ambiguities

List any place where the public contract was insufficient to reproduce the expected behavior without reading reference implementation internals.

This section is especially important. A documented ambiguity is useful specification evidence.

## 10. Evidence classification

Requested evidence level under [`EVIDENCE.md`](../EVIDENCE.md): E0 / E1 / E2 / E3 / E4 / E5 / E6 / E7

Requested interoperability level under [`INTEROPERABILITY.md`](../INTEROPERABILITY.md): I0 / I1 / I2 / I3 / I4 / I5 / I6

Why these levels are justified:

What evidence would be required to advance one level:

## 11. Reproduction

```bash
# exact setup and reproduction commands
```

State required environment variables, dependencies, clocks/timestamps, keys/test vectors, or network assumptions.

## 12. Result

Overall result: PASS / FAIL / MIXED / UNSUPPORTED

Short conclusion:

## 13. Claim boundary

This report does not automatically establish:

- whole-language compatibility;
- third-party adoption;
- market adoption;
- standards-body status or approval;
- security certification;
- regulatory compliance;
- scientific validation;
- official ĀRU authorization, endorsement, partnership, certification, or trademark rights.

Only claim what the exact tested evidence supports.

---

**The objective is not agreement with the reference implementation at any cost. The objective is a public contract precise enough that independent implementations can reproduce it, exchange artifacts, reject invalid inputs, and publish disagreement when they cannot.**
